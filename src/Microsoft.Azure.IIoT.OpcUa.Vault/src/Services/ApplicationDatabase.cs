// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace Microsoft.Azure.IIoT.OpcUa.Vault.Services {
    using Microsoft.Azure.IIoT.OpcUa.Vault.Models;
    using Microsoft.Azure.IIoT.OpcUa.Vault.Services.CosmosDB.Models;
    using Microsoft.Azure.IIoT.OpcUa.Registry;
    using Microsoft.Azure.IIoT.OpcUa.Registry.Models;
    using Microsoft.Azure.IIoT.Exceptions;
    using Microsoft.Azure.IIoT.Storage;
    using Autofac;
    using Serilog;
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Threading.Tasks;

    /// <summary>
    /// The default cosmos db based implementation of the application database.
    /// </summary>
    public sealed class ApplicationDatabase : IApplicationRegistry,
        IApplicationRegistry2 {

        /// <summary>
        /// Create database
        /// </summary>
        /// <param name="scope"></param>
        /// <param name="config"></param>
        /// <param name="db"></param>
        /// <param name="logger"></param>
        public ApplicationDatabase(ILifetimeScope scope,
            IVaultConfig config, IItemContainerFactory db, ILogger logger) {
            _scope = scope;
            _autoApprove = config.ApplicationsAutoApprove;
            _logger = logger;
            _applications = db.OpenAsync().Result.AsDocuments();

          //  // set unique key in CosmosDB for application ID
          //  db.UniqueKeyPolicy.UniqueKeys.Add(new UniqueKey {
          //      Paths = new Collection<string> {
          //          "/" + nameof(ApplicationDocument.ClassType),
          //          "/" + nameof(ApplicationDocument.ID)
          //      }
          //  });
        }

        /// <inheritdoc/>
        public async Task<ApplicationRegistrationResultModel> RegisterApplicationAsync(
            ApplicationRegistrationRequestModel request) {
            if (request == null) {
                throw new ArgumentNullException(nameof(request));
            }

            var recordId = await GetNextRecordIdAsync();
            var document = request.ToDocumentModel(recordId);

            // depending on use case, new applications can be auto approved.
            if (_autoApprove) {
                document.ApplicationState = ApplicationState.Approved;
                document.ApproveTime = document.CreateTime;
            }

            var result = await _applications.AddAsync(document);
            return new ApplicationRegistrationResultModel {
                Id = document.ApplicationId
            };
        }

        /// <inheritdoc/>
        public async Task<ApplicationRegistrationModel> GetApplicationAsync(
            string applicationId, bool filterInactiveEndpoints) {
            if (string.IsNullOrEmpty(applicationId)) {
                throw new ArgumentNullException(nameof(applicationId),
                    "The application id must be provided");
            }
            var application = await _applications.GetAsync<ApplicationDocument>(applicationId);
            return new ApplicationRegistrationModel {
                Application = application.Value.ToServiceModel()
            }.SetSecurityAssessment();
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
                document.Value.Patch(request);
                try {
                    await _applications.ReplaceAsync(document, document.Value);
                }
                catch (ResourceOutOfDateException) {
                    continue;
                }
                break;
            } 
        }

        /// <inheritdoc/>
        public Task ApproveApplicationAsync(string applicationId, bool force) {
            return UpdateApprovalState(applicationId, true, force);
        }

        /// <inheritdoc/>
        public Task RejectApplicationAsync(string applicationId, bool force) {
            return UpdateApprovalState(applicationId, false, force);
        }

        /// <inheritdoc/>
        public async Task UnregisterApplicationAsync(string applicationId) {
            if (string.IsNullOrEmpty(applicationId)) {
                throw new ArgumentNullException(nameof(applicationId),
                    "The application id must be provided");
            }
            var first = true;
            while (true) {
                var certificates = new List<byte[]>();
                var record = await _applications.GetAsync<ApplicationDocument>(applicationId);
                if (record == null) {
                    throw new ResourceNotFoundException(
                        "A record with the specified application id does not exist.");
                }
                if (record.Value.ApplicationState >= ApplicationState.Unregistered) {
                    throw new ResourceInvalidStateException(
                        "The record is not in a valid state for this operation.");
                }


                if (first && _scope != null) {
                    var certificateRequestsService = _scope.Resolve<ICertificateAuthority>();
                    // mark all requests as deleted
                    string nextPageLink = null;
                    do {
                        var result = await certificateRequestsService.QueryRequestsAsync(
                            applicationId, null, nextPageLink);
                        foreach (var request in result.Requests) {
                            if (request.State < CertificateRequestState.Deleted) {
                                await certificateRequestsService.DeleteRequestAsync(request.RequestId);
                            }
                        }
                        nextPageLink = result.NextPageLink;
                    } while (nextPageLink != null);
                }
                first = false;


                record.Value.ApplicationState = ApplicationState.Unregistered;
                record.Value.DeleteTime = DateTime.UtcNow;
                try {
                    await _applications.ReplaceAsync(record, record.Value);
                }
                catch (ResourceOutOfDateException) {
                    continue;
                }
                break;
            } 
        }

        /// <inheritdoc/>
        public async Task DeleteApplicationAsync(string applicationId, bool force) {
            if (string.IsNullOrEmpty(applicationId)) {
                throw new ArgumentNullException(nameof(applicationId),
                    "The application id must be provided");
            }

            var first = true;
            while (true) {
                var application = await _applications.GetAsync<ApplicationDocument>(applicationId);
                if (application == null) {
                    return;
                }
                if (!force &&
                    application.Value.ApplicationState < ApplicationState.Unregistered) {
                    throw new ResourceInvalidStateException(
                        "The record is not in a valid state for this operation.");
                }

                if (first && _scope != null) {
                    var certificateRequestsService = _scope.Resolve<ICertificateAuthority>();
                    // mark all requests as deleted
                    string nextPageLink = null;
                    do {
                        var result =
                            await certificateRequestsService.QueryRequestsAsync(
                                applicationId, null, nextPageLink);
                        foreach (var request in result.Requests) {
                            await certificateRequestsService.DeleteRequestAsync(request.RequestId);
                        }
                        nextPageLink = result.NextPageLink;
                    } while (nextPageLink != null);
                }
                first = false;


                try {
                    await _applications.DeleteAsync(application);
                }
                catch (ResourceOutOfDateException) {
                    // Try again
                    continue;
                }
                break;
            }
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
        public async Task<ApplicationInfoListModel> ListApplicationsAsync(
            string nextPageLink, int? pageSize) {
            var client = _applications.OpenSqlClient();
            var query = nextPageLink != null ?
                client.Continue<ApplicationDocument>(nextPageLink, pageSize) :
                client.Query<ApplicationDocument>(
                    "SELECT * FROM Applications a WHERE " +
        $"a.{nameof(ApplicationDocument.ClassType)} = {ApplicationDocument.ClassTypeName}",
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
                Applications = records.Select(a => a.ToServiceModel()).ToList(),
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
                queryParameters.Add("@maxRecordsToQuery", maxRecordsToQuery.ToString());
            }
            else {
                query = "SELECT";
            }
            query += " * FROM Applications a WHERE a.ID >= @startingRecord";
            queryParameters.Add("@startingRecord", startingRecordId.ToString());
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
                        query += " a.ApplicationState = " + sqlParm;
                        queryParameters.Add(sqlParm, state.ToString());
                        first = false;
                    }
                }
                if (!first) {
                    query += " )";
                }
            }
            query += " AND a.ClassType = " + ApplicationDocument.ClassTypeName;
            query += " ORDER BY a.ID";

            var client = _applications.OpenSqlClient();
            return client.Query<ApplicationDocument>(query, queryParameters, maxRecordsToQuery);
        }

        /// <summary>
        /// Update approval state
        /// </summary>
        /// <param name="applicationId"></param>
        /// <param name="approved"></param>
        /// <param name="force"></param>
        /// <returns></returns>
        public async Task UpdateApprovalState(string applicationId, bool approved, 
            bool force) {
            if (string.IsNullOrEmpty(applicationId)) {
                throw new ArgumentNullException(nameof(applicationId),
                    "The application id must be provided");
            }
            while (true) {
                var record = await _applications.GetAsync<ApplicationDocument>(applicationId);
                if (record == null) {
                    throw new ResourceNotFoundException(
                        "A record with the specified application id does not exist.");
                }
                if (!force &&
                    record.Value.ApplicationState != ApplicationState.New) {
                    throw new ResourceInvalidStateException(
                        "The record is not in a valid state for this operation.");
                }

                record.Value.ApplicationState = approved ?
                    ApplicationState.Approved : ApplicationState.Rejected;
                record.Value.ApproveTime = DateTime.UtcNow;

                try {
                    await _applications.ReplaceAsync(record, record.Value);
                }
                catch (ResourceOutOfDateException) {
                    continue;
                }
                break;
            }
        }

        /// <summary>
        /// Returns the next free, largest, application ID value.
        /// This is the ID value used for sorting in GDS queries.
        /// </summary>
        /// <returns></returns>
        private async Task<uint> GetNextRecordIdAsync() {
            try {
                var query = _applications.OpenSqlClient().Query<ApplicationDocument>(
                    "SELECT TOP 1 * FROM Applications a WHERE " +
                        $"a.{nameof(ApplicationDocument.ClassType)} = {ApplicationDocument.ClassTypeName} ORDER BY " +
                        $"a.{nameof(ApplicationDocument.ID)} DESC");

                var maxIDEnum = await query.AllAsync();
                var maxID = maxIDEnum.SingleOrDefault();
                return (maxID != null) ? maxID.Value.ID + 1 : 1;
            }
            catch {
                return 1;
            }
        }

        private const int kDefaultRecordsPerQuery = 10;
        private readonly ILogger _logger;
        private readonly IDocuments _applications;
        private readonly bool _autoApprove;
        private readonly ILifetimeScope _scope;
    }
}
