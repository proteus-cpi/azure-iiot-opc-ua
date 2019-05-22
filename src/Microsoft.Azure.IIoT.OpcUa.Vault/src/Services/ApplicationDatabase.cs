// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace Microsoft.Azure.IIoT.OpcUa.Vault.Services {
    using Microsoft.Azure.IIoT.OpcUa.Vault.Models;
    using Microsoft.Azure.IIoT.OpcUa.Vault.Services.Models;
    using Microsoft.Azure.IIoT.OpcUa.Registry;
    using Microsoft.Azure.IIoT.OpcUa.Registry.Models;
    using Microsoft.Azure.IIoT.Storage;
    using Microsoft.Azure.IIoT.Storage.Default;
    using Microsoft.Azure.IIoT.Exceptions;
    using Microsoft.Azure.IIoT.Utils;
    using Serilog;
    using System;
    using System.Collections.Concurrent;
    using System.Collections.Generic;
    using System.Linq;
    using System.Threading.Tasks;

    /// <summary>
    /// The default cosmos db based implementation of the application database.
    /// </summary>
    public sealed class ApplicationDatabase : IApplicationRegistry,
        IApplicationRegistry2, IApplicationRegistryEvents, IApplicationBulkProcessor {

        /// <summary>
        /// Create database
        /// </summary>
        /// <param name="listeners"></param>
        /// <param name="config"></param>
        /// <param name="db"></param>
        /// <param name="logger"></param>
        public ApplicationDatabase(IEnumerable<IApplicationRegistryListener> listeners,
            IVaultConfig config, IItemContainerFactory db, ILogger logger) {
            _config = config ?? throw new ArgumentNullException(nameof(config));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            if (db == null) {
                throw new ArgumentNullException(nameof(db));
            }
            var container = db.OpenAsync().Result;
            _applications = container.AsDocuments();
            _index = new ContainerIndex(container);
            _listeners = new ConcurrentDictionary<string, IApplicationRegistryListener>();
        }

        /// <inheritdoc/>
        public Action Register(IApplicationRegistryListener listener) {
            var token = Guid.NewGuid().ToString();
            _listeners.TryAdd(token, listener);
            return () => _listeners.TryRemove(token, out var _);
        }

        /// <inheritdoc/>
        public async Task<ApplicationRegistrationResultModel> RegisterApplicationAsync(
            ApplicationRegistrationRequestModel request) {
            if (request == null) {
                throw new ArgumentNullException(nameof(request));
            }

            var recordId = await _index.AllocateAsync();
            try {
                var document = request.ToDocumentModel(recordId);

                // depending on use case, new applications can be auto approved.
                var autoApprove = _config.ApplicationsAutoApprove;
                if (autoApprove) {
                    document.ApplicationState = ApplicationState.Approved;
                    document.ApproveTime = document.CreateTime;
                }

                var result = await _applications.AddAsync(document);

                var app = result.Value.ToServiceModel();
                await NotifyAllAsync(l => l.OnApplicationNewAsync(app)); // TODO:  Add authority id from context
                await NotifyAllAsync(l => l.OnApplicationEnabledAsync(app)); // TODO:  Add authority id from context
                if (autoApprove) {
                    await NotifyAllAsync(l => l.OnApplicationApprovedAsync(app)); // TODO:  Add authority id from context
                }

                return new ApplicationRegistrationResultModel {
                    Id = document.ApplicationId
                };
            }
            catch {
                await Try.Async(() => _index.FreeAsync(recordId));
                throw;
            }
        }

        /// <inheritdoc/>
        public async Task UpdateApplicationAsync(
            string applicationId, ApplicationRegistrationUpdateModel request) {
            if (request == null) {
                throw new ArgumentNullException(nameof(request),
                    "The application must be provided");
            }
            if (string.IsNullOrEmpty(applicationId)) {
                throw new ArgumentNullException(nameof(applicationId),
                    "The application id must be provided");
            }
            while (true) {
                var document = await _applications.GetAsync<ApplicationDocument>(applicationId);
                if (document == null) {
                    throw new ResourceNotFoundException("Application does not exist");
                }
                var application = document.Value.Clone();
                application.Patch(request);
                try {
                    var result = await _applications.ReplaceAsync(document, application);
                    var app = result.Value.ToServiceModel();
                    await NotifyAllAsync(l => l.OnApplicationUpdatedAsync(app)); // TODO:  Add authority id from context
                    break;
                }
                catch (ResourceOutOfDateException) {
                    _logger.Verbose("Retry update application operation.");
                    continue;
                }
            }
        }

        /// <inheritdoc/>
        public async Task ApproveApplicationAsync(string applicationId, bool force) {
            var app = await UpdateApplicationStateAsync(applicationId, ApplicationState.Approved,
                s => s == ApplicationState.New || force);
            await NotifyAllAsync(l => l.OnApplicationApprovedAsync(app)); // TODO:  Add authority id from context
        }

        /// <inheritdoc/>
        public async Task RejectApplicationAsync(string applicationId, bool force) {
            var app = await UpdateApplicationStateAsync(applicationId, ApplicationState.Rejected,
                s => s == ApplicationState.New || force);
            await NotifyAllAsync(l => l.OnApplicationRejectedAsync(app)); // TODO:  Add authority id from context
        }

        /// <inheritdoc/>
        public async Task UnregisterApplicationAsync(string applicationId) {
            if (string.IsNullOrEmpty(applicationId)) {
                throw new ArgumentNullException(nameof(applicationId),
                    "The application id must be provided");
            }
            while (true) {
                var document = await _applications.GetAsync<ApplicationDocument>(applicationId);
                if (document == null) {
                    throw new ResourceNotFoundException(
                        "A record with the specified application id does not exist.");
                }
                var application = document.Value.Clone();
                try {
                    // Try delete
                    await _applications.DeleteAsync(document);

                    // Success -- Notify others to clean up
                    var app = document.Value.ToServiceModel();
                    await NotifyAllAsync(l => l.OnApplicationDeletedAsync(app)); // TODO:  Add authority id from context

                    // Try free record id
                    await Try.Async(() => _index.FreeAsync(document.Value.ID));
                    break;
                }
                catch (ResourceOutOfDateException) {
                    _logger.Verbose("Retry unregister application operation.");
                    continue;
                }
            }
        }

        /// <inheritdoc/>
        public async Task DisableApplicationAsync(string applicationId) {
            var app = await UpdateEnabledDisabledAsync(applicationId, false);
            await NotifyAllAsync(l => l.OnApplicationDisabledAsync(app)); // TODO:  Add authority id from context
        }

        /// <inheritdoc/>
        public async Task EnableApplicationAsync(string applicationId) {
            var app = await UpdateEnabledDisabledAsync(applicationId, true);
            await NotifyAllAsync(l => l.OnApplicationEnabledAsync(app)); // TODO:  Add authority id from context
        }

        /// <inheritdoc/>
        public Task PurgeDisabledApplicationsAsync(TimeSpan notSeenFor) {
            // TODO: Implement correctly
            return Task.CompletedTask;
        }

        /// <inheritdoc/>
        public Task<ApplicationSiteListModel> ListSitesAsync(string nextPageLink,
            int? pageSize) {
            // TODO: Implement correctly
            return Task.FromResult(new ApplicationSiteListModel());
        }

        /// <inheritdoc/>
        public async Task<ApplicationRegistrationModel> GetApplicationAsync(
            string applicationId, bool filterInactiveEndpoints) {
            if (string.IsNullOrEmpty(applicationId)) {
                throw new ArgumentNullException(nameof(applicationId),
                    "The application id must be provided");
            }
            var document = await _applications.GetAsync<ApplicationDocument>(applicationId);
            if (document == null) {
                throw new ResourceNotFoundException("No such application");
            }
            return new ApplicationRegistrationModel {
                Application = document.Value.ToServiceModel()
            }.SetSecurityAssessment();
        }

        /// <inheritdoc/>
        public async Task<ApplicationInfoListModel> ListApplicationsAsync(
            string nextPageLink, int? pageSize) {
            var client = _applications.OpenSqlClient();
            var query = nextPageLink != null ?
                client.Continue<ApplicationDocument>(nextPageLink, pageSize) :
                client.Query<ApplicationDocument>(
                    "SELECT * FROM Applications a WHERE " +
        $"a.{nameof(ApplicationDocument.ClassType)} = '{ApplicationDocument.ClassTypeName}'",
                null, pageSize);
            // Read results
            var results = await query.ReadAsync();
            return new ApplicationInfoListModel {
                Items = results.Select(r => r.Value.ToServiceModel()).ToList()
            };
        }

        /// <inheritdoc/>
        public async Task<QueryApplicationsByIdResultModel> QueryApplicationsByIdAsync(
            QueryApplicationsByIdRequestModel request) {

            // TODO: implement last query time
            var lastCounterResetTime = DateTime.MinValue;
            var records = new List<ApplicationDocument>();
            var matchQuery = false;
            var complexQuery =
                !string.IsNullOrEmpty(request.ApplicationName) ||
                !string.IsNullOrEmpty(request.ApplicationUri) ||
                !string.IsNullOrEmpty(request.ProductUri) ||
                (request.ServerCapabilities != null && request.ServerCapabilities.Count > 0);
            if (complexQuery) {
                matchQuery =
                    Opc.Ua.Gds.Server.Database.ApplicationsDatabaseBase.IsMatchPattern(
                        request.ApplicationName) ||
                    Opc.Ua.Gds.Server.Database.ApplicationsDatabaseBase.IsMatchPattern(
                        request.ApplicationUri) ||
                    Opc.Ua.Gds.Server.Database.ApplicationsDatabaseBase.IsMatchPattern(
                        request.ProductUri);
            }

            var nextRecordId = request.StartingRecordId ?? 0;
            var maxRecordsToReturn = request.MaxRecordsToReturn ?? 0;
            var lastQuery = false;
            do {
                var queryRecords = complexQuery ? kDefaultRecordsPerQuery : maxRecordsToReturn;
                var query = CreateServerQuery(nextRecordId, (int)queryRecords,
                    request.ApplicationState);
                nextRecordId++;
                var applications = await query.ReadAsync();
                lastQuery = queryRecords == 0 || applications.Count() < queryRecords;
                foreach (var application in applications.Select(a => a.Value)) {
                    nextRecordId = application.ID + 1;
                    if (!string.IsNullOrEmpty(request.ApplicationName)) {
                        if (!Opc.Ua.Gds.Server.Database.ApplicationsDatabaseBase.Match(
                            application.ApplicationName, request.ApplicationName)) {
                            continue;
                        }
                    }
                    if (!string.IsNullOrEmpty(request.ApplicationUri)) {
                        if (!Opc.Ua.Gds.Server.Database.ApplicationsDatabaseBase.Match(
                            application.ApplicationUri, request.ApplicationUri)) {
                            continue;
                        }
                    }
                    if (!string.IsNullOrEmpty(request.ProductUri)) {
                        if (!Opc.Ua.Gds.Server.Database.ApplicationsDatabaseBase.Match(
                            application.ProductUri, request.ProductUri)) {
                            continue;
                        }
                    }

                    string[] capabilities = null;
                    if (!string.IsNullOrEmpty(application.ServerCapabilities)) {
                        capabilities = application.ServerCapabilities.Split(',');
                    }
                    if (request.ServerCapabilities != null && request.ServerCapabilities.Count > 0) {
                        var match = true;
                        foreach (var cap in request.ServerCapabilities) {
                            if (capabilities == null || !capabilities.Contains(cap)) {
                                match = false;
                                break;
                            }
                        }
                        if (!match) {
                            continue;
                        }
                    }
                    records.Add(application);
                    if (maxRecordsToReturn > 0 && --maxRecordsToReturn == 0) {
                        break;
                    }
                }
            } while (maxRecordsToReturn > 0 && !lastQuery);
            if (lastQuery) {
                nextRecordId = 0;
            }
            return new QueryApplicationsByIdResultModel {
                Items = records.Select(a => a.ToServiceModel()).ToList(),
                LastCounterResetTime = lastCounterResetTime,
                NextRecordId = nextRecordId
            };
        }

        /// <inheritdoc/>
        public async Task<ApplicationInfoListModel> QueryApplicationsAsync(
            ApplicationRegistrationQueryModel request, int? maxRecordsToReturn) {
            var records = new List<ApplicationDocument>();
            var matchQuery = false;
            var complexQuery =
                !string.IsNullOrEmpty(request.ApplicationName) ||
                !string.IsNullOrEmpty(request.ApplicationUri) ||
                !string.IsNullOrEmpty(request.ProductUri) ||
                !string.IsNullOrEmpty(request.Capability);

            if (complexQuery) {
                matchQuery =
                    Opc.Ua.Gds.Server.Database.ApplicationsDatabaseBase.IsMatchPattern(
                        request.ApplicationName) ||
                    Opc.Ua.Gds.Server.Database.ApplicationsDatabaseBase.IsMatchPattern(
                        request.ApplicationUri) ||
                    Opc.Ua.Gds.Server.Database.ApplicationsDatabaseBase.IsMatchPattern(
                        request.ProductUri);
            }

            if (maxRecordsToReturn == null || maxRecordsToReturn < 0) {
                maxRecordsToReturn = kDefaultRecordsPerQuery;
            }
            var query = CreateServerQuery(0, maxRecordsToReturn.Value, request.State);
            while (query.HasMore()) {
                var applications = await query.ReadAsync();
                foreach (var application in applications.Select(a => a.Value)) {
                    if (!string.IsNullOrEmpty(request.ApplicationName)) {
                        if (!Opc.Ua.Gds.Server.Database.ApplicationsDatabaseBase.Match(
                            application.ApplicationName, request.ApplicationName)) {
                            continue;
                        }
                    }
                    if (!string.IsNullOrEmpty(request.ApplicationUri)) {
                        if (!Opc.Ua.Gds.Server.Database.ApplicationsDatabaseBase.Match(
                            application.ApplicationUri, request.ApplicationUri)) {
                            continue;
                        }
                    }
                    if (!string.IsNullOrEmpty(request.ProductUri)) {
                        if (!Opc.Ua.Gds.Server.Database.ApplicationsDatabaseBase.Match(
                            application.ProductUri, request.ProductUri)) {
                            continue;
                        }
                    }
                    if (!string.IsNullOrEmpty(request.Capability)) {
                        if (!string.IsNullOrEmpty(application.ServerCapabilities) ||
                            !application.ServerCapabilities.Contains(request.Capability)) {
                            continue;
                        }
                    }
                    records.Add(application);
                    if (maxRecordsToReturn > 0 && records.Count >= maxRecordsToReturn) {
                        break;
                    }
                }
            }
            return new ApplicationInfoListModel {
                Items = records.Select(a => a.ToServiceModel()).ToList(),
                ContinuationToken = null
            };
        }

        /// <inheritdoc/>
        public Task ProcessDiscoveryEventsAsync(string siteId, string supervisorId, 
            DiscoveryResultModel result, IEnumerable<DiscoveryEventModel> events) => 
            throw new NotImplementedException();

        /// <summary>
        /// Helper to create a SQL query for CosmosDB.
        /// </summary>
        /// <param name="startingRecordId">The first record Id</param>
        /// <param name="maxRecordsToQuery">The max number of records</param>
        /// <param name="applicationState">The application state query filter</param>
        /// <returns></returns>
        private IResultFeed<IDocumentInfo<ApplicationDocument>> CreateServerQuery(
            uint startingRecordId, int maxRecordsToQuery, ApplicationStateMask? applicationState) {
            string query;
            var queryParameters = new Dictionary<string, object>();
            if (maxRecordsToQuery != 0) {
                query = "SELECT TOP @maxRecordsToQuery";
                queryParameters.Add("@maxRecordsToQuery", maxRecordsToQuery);
            }
            else {
                query = "SELECT";
            }
            query += $" * FROM Applications a WHERE a.{nameof(ApplicationDocument.ID)} >= @startingRecord";
            queryParameters.Add("@startingRecord", startingRecordId);
            var queryState = applicationState ?? ApplicationStateMask.Approved;
            if (queryState != 0) {
                var first = true;
                foreach (ApplicationStateMask state in Enum.GetValues(
                    typeof(ApplicationStateMask))) {
                    if (state == 0) {
                        continue;
                    }

                    if ((queryState & state) == state) {
                        var sqlParm = "@" + state.ToString().ToLower();
                        if (first) {
                            query += " AND (";
                        }
                        else {
                            query += " OR";
                        }
                        query += $" a.{nameof(ApplicationDocument.ApplicationState)} = {sqlParm}";
                        queryParameters.Add(sqlParm, state.ToString());
                        first = false;
                    }
                }
                if (!first) {
                    query += " )";
                }
            }
            query += $" AND a.{ nameof(ApplicationDocument.ClassType)} = @classType";
            queryParameters.Add("@classType", ApplicationDocument.ClassTypeName);
            query += $" ORDER BY a.{nameof(ApplicationDocument.ID)}";

            var client = _applications.OpenSqlClient();
            return client.Query<ApplicationDocument>(query, queryParameters, maxRecordsToQuery);
        }

        /// <summary>
        /// Update enabled or disabled state
        /// </summary>
        /// <param name="applicationId"></param>
        /// <param name="enabled"></param>
        /// <returns></returns>
        public async Task<ApplicationInfoModel> UpdateEnabledDisabledAsync(string applicationId,
            bool enabled) {
            if (string.IsNullOrEmpty(applicationId)) {
                throw new ArgumentNullException(nameof(applicationId),
                    "The application id must be provided");
            }
            while (true) {
                var document = await _applications.GetAsync<ApplicationDocument>(applicationId);
                if (document == null) {
                    throw new ResourceNotFoundException(
                        "A record with the specified application id does not exist.");
                }
                var application = document.Value.Clone();

                if ((enabled && application.NotSeenSince == null) ||
                    (!enabled && application.NotSeenSince != null)) {
                    throw new ResourceInvalidStateException(
                        "The record is not in a valid state for this operation.");
                }

                application.NotSeenSince = enabled ? (DateTime?)null : DateTime.UtcNow;
                try {
                    var result = await _applications.ReplaceAsync(document, application);
                    return result.Value.ToServiceModel();
                }
                catch (ResourceOutOfDateException) {
                    _logger.Verbose("Retry update application disable/enable operation.");
                    continue;
                }
            }
        }

        /// <summary>
        /// Update application state
        /// </summary>
        /// <param name="applicationId"></param>
        /// <param name="state"></param>
        /// <param name="precondition"></param>
        /// <returns></returns>
        public async Task<ApplicationInfoModel> UpdateApplicationStateAsync(string applicationId,
            ApplicationState state, Func<ApplicationState, bool> precondition) {
            if (string.IsNullOrEmpty(applicationId)) {
                throw new ArgumentNullException(nameof(applicationId),
                    "The application id must be provided");
            }
            while (true) {
                var document = await _applications.GetAsync<ApplicationDocument>(applicationId);
                if (document == null) {
                    throw new ResourceNotFoundException(
                        "A record with the specified application id does not exist.");
                }
                if (precondition != null && !precondition(document.Value.ApplicationState)) {
                    throw new ResourceInvalidStateException(
                        "The record is not in a valid state for this operation.");
                }

                var application = document.Value.Clone();
                application.ApplicationState = state;
                application.ApproveTime = DateTime.UtcNow;
                try {
                    var result = await _applications.ReplaceAsync(document, application);
                    return result.Value.ToServiceModel();
                }
                catch (ResourceOutOfDateException) {
                    _logger.Verbose("Retry update application state operation.");
                    continue;
                }
            }
        }

        /// <summary>
        /// Call listeners
        /// </summary>
        /// <param name="evt"></param>
        /// <returns></returns>
        private Task NotifyAllAsync(Func<IApplicationRegistryListener, Task> evt) {
            return Task
                .WhenAll(_listeners.Select(l => evt(l.Value)).ToArray())
                .ContinueWith(t => Task.CompletedTask);
        }

        private const int kDefaultRecordsPerQuery = 10;
        private readonly ILogger _logger;
        private readonly IContainerIndex _index;
        private readonly IDocuments _applications;
        private readonly IVaultConfig _config;
        private readonly ConcurrentDictionary<string, IApplicationRegistryListener> _listeners;
    }
}
