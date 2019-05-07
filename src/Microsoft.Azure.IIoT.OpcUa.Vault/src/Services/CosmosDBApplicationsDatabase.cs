// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------


namespace Microsoft.Azure.IIoT.OpcUa.Vault.Services {
    using Autofac;
    using Microsoft.Azure.Documents;
    using Microsoft.Azure.IIoT.Exceptions;
    using Microsoft.Azure.IIoT.OpcUa.Registry.Models;
    using Microsoft.Azure.IIoT.OpcUa.Vault.CosmosDB;
    using Microsoft.Azure.IIoT.OpcUa.Vault.CosmosDB.Models;
    using Microsoft.Azure.IIoT.OpcUa.Vault.CosmosDB.Services;
    using Microsoft.Azure.IIoT.OpcUa.Vault.Models;
    using Serilog;
    using System;
    using System.Collections.Generic;
    using System.Collections.ObjectModel;
    using System.Linq;
    using System.Net;
    using System.Text;
    using System.Threading.Tasks;

    /// <summary>
    /// The CosmosDB implementation of the application database.
    /// </summary>
    public sealed class CosmosDBApplicationsDatabase : IApplicationsDatabase {

        /// <summary>
        /// Create database
        /// </summary>
        /// <param name="scope"></param>
        /// <param name="config"></param>
        /// <param name="db"></param>
        /// <param name="logger"></param>
        public CosmosDBApplicationsDatabase(ILifetimeScope scope,
            IVaultConfig config, IDocumentDBRepository db, ILogger logger) {
            _scope = scope;
            _autoApprove = config.ApplicationsAutoApprove;
            _logger = logger;
            _logger.Debug("Creating new instance of `CosmosDBApplicationsDatabase` service " +
                config.CosmosDBCollection);
            // set unique key in CosmosDB for application ID
            db.UniqueKeyPolicy.UniqueKeys.Add(new UniqueKey {
                Paths = new Collection<string> {
                    "/" + nameof(ApplicationDocument.ClassType),
                    "/" + nameof(ApplicationDocument.ID)
                }
            });
            _applications = new DocumentDBCollection<ApplicationDocument>(
                db, config.CosmosDBCollection);
        }

        /// <inheritdoc/>
        public async Task InitializeAsync() {
            await _applications.CreateCollectionIfNotExistsAsync();
            _appIdCounter = await GetMaxAppIDAsync();
        }

        /// <inheritdoc/>
        public async Task<ApplicationRecordModel> RegisterApplicationAsync(
            ApplicationRecordModel application) {
            var document = application.ToDocumentModel();
            var applicationId = VerifyRegisterApplication(document);
            if (Guid.Empty != applicationId) {
                return await UpdateApplicationAsync(
                    application.ApplicationId.ToString(), application);
            }

            // normalize Server Caps
            document.ServerCapabilities = ServerCapabilities(document);
            document.ApplicationId = Guid.NewGuid();
            document.ID = _appIdCounter++;
            document.ApplicationState = ApplicationState.New;
            document.CreateTime = DateTime.UtcNow;

            // depending on use case, new applications can be auto approved.
            if (_autoApprove) {
                document.ApplicationState = ApplicationState.Approved;
                document.ApproveTime = document.CreateTime;
            }
            bool retry;
            string resourceId = null;
            do {
                retry = false;
                try {
                    var result = await _applications.CreateAsync(document);
                    resourceId = result.Id;
                }
                catch (DocumentClientException dce) {
                    if (dce.StatusCode == System.Net.HttpStatusCode.Conflict) {
                        // retry with new guid and keys
                        document.ApplicationId = Guid.NewGuid();
                        _appIdCounter = await GetMaxAppIDAsync();
                        document.ID = _appIdCounter++;
                        retry = true;
                    }
                }
            } while (retry);
            return await GetApplicationAsync(applicationId.ToString());
        }

        /// <inheritdoc/>
        public async Task<ApplicationRecordModel> GetApplicationAsync(
            string applicationId) {
            var appId = ToGuidAndVerify(applicationId);
            var application = await _applications.GetAsync(appId);
            return application.ToServiceModel();
        }

        /// <inheritdoc/>
        public async Task<ApplicationRecordModel> UpdateApplicationAsync(
            string applicationId, ApplicationRecordModel application) {
            if (application == null) {
                throw new ArgumentNullException(nameof(application),
                    "The application must be provided");
            }

            var document = application.ToDocumentModel();
            var appGuid = ToGuidAndVerify(applicationId);
            var recordId = VerifyRegisterApplication(document);

            var capabilities = ServerCapabilities(document);

            bool retryUpdate;
            do {
                retryUpdate = false;

                var record = await _applications.GetAsync(appGuid);
                if (record == null) {
                    throw new ResourceNotFoundException(
                        "A record with the specified application id does not exist.");
                }

                if (record.ID == 0) {
                    record.ID = await GetMaxAppIDAsync();
                }

                record.UpdateTime = DateTime.UtcNow;
                record.ApplicationUri = document.ApplicationUri;
                record.ApplicationName = document.ApplicationName;
                record.ApplicationType = document.ApplicationType;
                record.ProductUri = document.ProductUri;
                record.ServerCapabilities = capabilities;
                record.ApplicationNames = document.ApplicationNames;
                record.DiscoveryUrls = document.DiscoveryUrls;
                try {
                    await _applications.UpdateAsync(appGuid, record, record.ETag);
                }
                catch (DocumentClientException dce) {
                    if (dce.StatusCode == HttpStatusCode.PreconditionFailed) {
                        retryUpdate = true;
                    }
                }
            } while (retryUpdate);
            document = await _applications.GetAsync(appGuid);
            return document.ToServiceModel();
        }

        /// <inheritdoc/>
        public async Task<ApplicationRecordModel> ApproveApplicationAsync(
            string applicationId, bool approved, bool force) {
            var appId = ToGuidAndVerify(applicationId);
            bool retryUpdate;
            ApplicationDocument record;
            do {
                retryUpdate = false;
                record = await _applications.GetAsync(appId);
                if (record == null) {
                    throw new ResourceNotFoundException(
                        "A record with the specified application id does not exist.");
                }
                if (!force &&
                    record.ApplicationState != ApplicationState.New) {
                    throw new ResourceInvalidStateException(
                        "The record is not in a valid state for this operation.");
                }

                record.ApplicationState = approved ?
                    ApplicationState.Approved : ApplicationState.Rejected;
                record.ApproveTime = DateTime.UtcNow;

                try {
                    await _applications.UpdateAsync(appId, record, record.ETag);
                }
                catch (DocumentClientException dce) {
                    if (dce.StatusCode == HttpStatusCode.PreconditionFailed) {
                        retryUpdate = true;
                    }
                }
            } while (retryUpdate);
            return record.ToServiceModel();
        }

        /// <inheritdoc/>
        public async Task<ApplicationRecordModel> UnregisterApplicationAsync(
            string applicationId) {
            var appId = ToGuidAndVerify(applicationId);
            bool retryUpdate;
            var first = true;
            ApplicationDocument record;
            do {
                retryUpdate = false;

                var certificates = new List<byte[]>();

                record = await _applications.GetAsync(appId);
                if (record == null) {
                    throw new ResourceNotFoundException(
                        "A record with the specified application id does not exist.");
                }

                if (record.ApplicationState >= ApplicationState.Unregistered) {
                    throw new ResourceInvalidStateException(
                        "The record is not in a valid state for this operation.");
                }

                if (first && _scope != null) {
                    var certificateRequestsService = _scope.Resolve<ICertificateRequest>();
                    // mark all requests as deleted
                    ReadRequestResultModel[] certificateRequests;
                    string nextPageLink = null;
                    do {
                        (nextPageLink, certificateRequests) = await certificateRequestsService.QueryPageAsync(
                            appId.ToString(), null, nextPageLink);
                        foreach (var request in certificateRequests) {
                            if (request.State < CertificateRequestState.Deleted) {
                                await certificateRequestsService.DeleteAsync(request.RequestId);
                            }
                        }
                    } while (nextPageLink != null);
                }
                first = false;

                record.ApplicationState = ApplicationState.Unregistered;
                record.DeleteTime = DateTime.UtcNow;

                try {
                    await _applications.UpdateAsync(appId, record, record.ETag);
                }
                catch (DocumentClientException dce) {
                    if (dce.StatusCode == HttpStatusCode.PreconditionFailed) {
                        retryUpdate = true;
                    }
                }
            } while (retryUpdate);
            return record.ToServiceModel();
        }

        /// <inheritdoc/>
        public async Task DeleteApplicationAsync(string applicationId, bool force) {
            var appId = ToGuidAndVerify(applicationId);
            var application = await _applications.GetAsync(appId);
            if (!force &&
                application.ApplicationState < ApplicationState.Unregistered) {
                throw new ResourceInvalidStateException(
                    "The record is not in a valid state for this operation.");
            }

            if (_scope != null) {
                var certificateRequestsService = _scope.Resolve<ICertificateRequest>();
                // mark all requests as deleted
                ReadRequestResultModel[] certificateRequests;
                string nextPageLink = null;
                do {
                    (nextPageLink, certificateRequests) =
                        await certificateRequestsService.QueryPageAsync(
                            appId.ToString(), null, nextPageLink);
                    foreach (var request in certificateRequests) {
                        await certificateRequestsService.DeleteAsync(request.RequestId);
                    }
                } while (nextPageLink != null);
            }
            await _applications.DeleteAsync(appId);
        }

        /// <inheritdoc/>
        public async Task<IList<ApplicationRecordModel>> ListApplicationAsync(string applicationUri) {
            if (string.IsNullOrEmpty(applicationUri)) {
                throw new ArgumentNullException(nameof(applicationUri),
                    "The applicationUri must be provided.");
            }
            if (!Uri.IsWellFormedUriString(applicationUri, UriKind.Absolute)) {
                throw new ArgumentException(
                    "The applicationUri is invalid.", nameof(applicationUri));
            }

            var queryParameters = new SqlParameterCollection();
            var query = "SELECT * FROM Applications a WHERE";
            query += " a.ApplicationUri = @applicationUri";
            queryParameters.Add(new SqlParameter("@applicationUri", applicationUri));
            query += " AND a.ApplicationState = @applicationState";
            queryParameters.Add(new SqlParameter("@applicationState",
                ApplicationState.Approved.ToString()));
            query += " AND a.ClassType = @classType";
            queryParameters.Add(new SqlParameter("@classType", ApplicationDocument.ClassTypeName));
            var sqlQuerySpec = new SqlQuerySpec {
                QueryText = query,
                Parameters = queryParameters
            };
            var sqlResults = await _applications.GetAsync(sqlQuerySpec);
            return sqlResults.Select(r => r.ToServiceModel()).ToList();
        }

        /// <inheritdoc/>
        public async Task<QueryApplicationsByIdResponseModel> QueryApplicationsByIdAsync(
            uint startingRecordId,
            uint maxRecordsToReturn,
            string applicationName,
            string applicationUri,
            uint applicationType,
            string productUri,
            IList<string> serverCapabilities,
            QueryApplicationState? applicationState
            ) {
            // TODO: implement last query time
            var lastCounterResetTime = DateTime.MinValue;
            uint nextRecordId = 0;

            var records = new List<ApplicationDocument>();

            var matchQuery = false;
            var complexQuery =
                !string.IsNullOrEmpty(applicationName) ||
                !string.IsNullOrEmpty(applicationUri) ||
                !string.IsNullOrEmpty(productUri) ||
                (serverCapabilities != null && serverCapabilities.Count > 0);

            if (complexQuery) {
                matchQuery =
                    Opc.Ua.Gds.Server.Database.ApplicationsDatabaseBase.IsMatchPattern(applicationName) ||
                    Opc.Ua.Gds.Server.Database.ApplicationsDatabaseBase.IsMatchPattern(applicationUri) ||
                    Opc.Ua.Gds.Server.Database.ApplicationsDatabaseBase.IsMatchPattern(productUri);
            }

            var lastQuery = false;
            do {
                var queryRecords = complexQuery ? _defaultRecordsPerQuery : maxRecordsToReturn;
                var sqlQuerySpec = CreateServerQuery(startingRecordId, queryRecords, applicationState);
                nextRecordId = startingRecordId + 1;
                var applications = await _applications.GetAsync(sqlQuerySpec);
                lastQuery = queryRecords == 0 ||
                    applications.Count() < queryRecords || !applications.Any();

                foreach (var application in applications) {
                    startingRecordId = (uint)application.ID + 1;
                    nextRecordId = startingRecordId;

                    if (!string.IsNullOrEmpty(applicationName)) {
                        if (!Opc.Ua.Gds.Server.Database.ApplicationsDatabaseBase.Match(
                            application.ApplicationName, applicationName)) {
                            continue;
                        }
                    }

                    if (!string.IsNullOrEmpty(applicationUri)) {
                        if (!Opc.Ua.Gds.Server.Database.ApplicationsDatabaseBase.Match(
                            application.ApplicationUri, applicationUri)) {
                            continue;
                        }
                    }

                    if (!string.IsNullOrEmpty(productUri)) {
                        if (!Opc.Ua.Gds.Server.Database.ApplicationsDatabaseBase.Match(
                            application.ProductUri, productUri)) {
                            continue;
                        }
                    }

                    string[] capabilities = null;
                    if (!string.IsNullOrEmpty(application.ServerCapabilities)) {
                        capabilities = application.ServerCapabilities.Split(',');
                    }

                    if (serverCapabilities != null && serverCapabilities.Count > 0) {
                        var match = true;
                        for (var ii = 0; ii < serverCapabilities.Count; ii++) {
                            if (capabilities == null || !capabilities.Contains(serverCapabilities[ii])) {
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
            return new QueryApplicationsByIdResponseModel {
                Applications = records.Select(a => a.ToServiceModel()).ToList(),
                LastCounterResetTime = lastCounterResetTime,
                NextRecordId = nextRecordId
            };
        }

        /// <inheritdoc/>
        public async Task<QueryApplicationsResponseModel> QueryApplicationsAsync(
            string applicationName, string applicationUri, uint applicationType,
            string productUri, IList<string> serverCapabilities,
            QueryApplicationState? applicationState, string nextPageLink,
            int? maxRecordsToReturn) {
            var records = new List<ApplicationDocument>();
            var matchQuery = false;
            var complexQuery =
                !string.IsNullOrEmpty(applicationName) ||
                !string.IsNullOrEmpty(applicationUri) ||
                !string.IsNullOrEmpty(productUri) ||
                (serverCapabilities != null && serverCapabilities.Count > 0);

            if (complexQuery) {
                matchQuery =
                    Opc.Ua.Gds.Server.Database.ApplicationsDatabaseBase.IsMatchPattern(applicationName) ||
                    Opc.Ua.Gds.Server.Database.ApplicationsDatabaseBase.IsMatchPattern(applicationUri) ||
                    Opc.Ua.Gds.Server.Database.ApplicationsDatabaseBase.IsMatchPattern(productUri);
            }

            if (maxRecordsToReturn < 0) {
                maxRecordsToReturn = _defaultRecordsPerQuery;
            }
            var sqlQuerySpec = CreateServerQuery(0, 0, applicationState);
            do {
                IEnumerable<ApplicationDocument> applications;
                (nextPageLink, applications) = await _applications.GetPageAsync(
                    sqlQuerySpec, nextPageLink, maxRecordsToReturn - records.Count);

                foreach (var application in applications) {
                    if (!string.IsNullOrEmpty(applicationName)) {
                        if (!Opc.Ua.Gds.Server.Database.ApplicationsDatabaseBase.Match(
                            application.ApplicationName, applicationName)) {
                            continue;
                        }
                    }

                    if (!string.IsNullOrEmpty(applicationUri)) {
                        if (!Opc.Ua.Gds.Server.Database.ApplicationsDatabaseBase.Match(
                            application.ApplicationUri, applicationUri)) {
                            continue;
                        }
                    }

                    if (!string.IsNullOrEmpty(productUri)) {
                        if (!Opc.Ua.Gds.Server.Database.ApplicationsDatabaseBase.Match(
                            application.ProductUri, productUri)) {
                            continue;
                        }
                    }

                    string[] capabilities = null;
                    if (!string.IsNullOrEmpty(application.ServerCapabilities)) {
                        capabilities = application.ServerCapabilities.Split(',');
                    }

                    if (serverCapabilities != null && serverCapabilities.Count > 0) {
                        var match = true;
                        for (var ii = 0; ii < serverCapabilities.Count; ii++) {
                            if (capabilities == null || !capabilities.Contains(serverCapabilities[ii])) {
                                match = false;
                                break;
                            }
                        }
                        if (!match) {
                            continue;
                        }
                    }
                    records.Add(application);
                    if (maxRecordsToReturn > 0 && records.Count >= maxRecordsToReturn) {
                        break;
                    }
                }
            } while (nextPageLink != null);
            return new QueryApplicationsResponseModel {
                Applications = records.Select(a => a.ToServiceModel()).ToList(),
                NextPageLink = nextPageLink
            };
        }

        /// <summary>
        /// Helper to create a SQL query for CosmosDB.
        /// </summary>
        /// <param name="startingRecordId">The first record Id</param>
        /// <param name="maxRecordsToQuery">The max number of records</param>
        /// <param name="applicationState">The application state query filter</param>
        /// <returns></returns>
        private SqlQuerySpec CreateServerQuery(uint startingRecordId,
            uint maxRecordsToQuery, QueryApplicationState? applicationState) {
            string query;
            var queryParameters = new SqlParameterCollection();
            if (maxRecordsToQuery != 0) {
                query = "SELECT TOP @maxRecordsToQuery";
                queryParameters.Add(new SqlParameter("@maxRecordsToQuery", maxRecordsToQuery));
            }
            else {
                query = "SELECT";
            }
            query += " * FROM Applications a WHERE a.ID >= @startingRecord";
            queryParameters.Add(new SqlParameter("@startingRecord", startingRecordId));
            var queryState = applicationState ?? QueryApplicationState.Approved;
            if (queryState != 0) {
                var first = true;
                foreach (QueryApplicationState state in Enum.GetValues(
                    typeof(QueryApplicationState))) {
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
                        queryParameters.Add(new SqlParameter(sqlParm, state.ToString()));
                        first = false;
                    }
                }
                if (!first) {
                    query += " )";
                }
            }
            query += " AND a.ClassType = @classType";
            queryParameters.Add(new SqlParameter("@classType", ApplicationDocument.ClassTypeName));
            query += " ORDER BY a.ID";
            var sqlQuerySpec = new SqlQuerySpec {
                QueryText = query,
                Parameters = queryParameters
            };
            return sqlQuerySpec;
        }

        /// <summary>
        /// Validates all fields in an application record to be consistent with
        /// the OPC UA specification.
        /// </summary>
        /// <param name="application">The application</param>
        /// <returns>The application Guid.</returns>
        private Guid VerifyRegisterApplication(ApplicationDocument application) {
            if (application == null) {
                throw new ArgumentNullException(nameof(application));
            }

            if (application.ApplicationUri == null) {
                throw new ArgumentNullException(nameof(application.ApplicationUri));
            }

            if (!Uri.IsWellFormedUriString(application.ApplicationUri, UriKind.Absolute)) {
                throw new ArgumentException(application.ApplicationUri +
                    " is not a valid URI.", nameof(application.ApplicationUri));
            }

            if ((application.ApplicationType < ApplicationType.Server) ||
                (application.ApplicationType > ApplicationType.DiscoveryServer)) {
                throw new ArgumentException(application.ApplicationType.ToString() +
                    " is not a valid ApplicationType.", nameof(application.ApplicationType));
            }

            if (application.ApplicationNames == null ||
                application.ApplicationNames.Length == 0 ||
                string.IsNullOrEmpty(application.ApplicationNames[0].Text)) {
                throw new ArgumentException(
                    "At least one ApplicationName must be provided.",
                    nameof(application.ApplicationNames));
            }

            if (string.IsNullOrEmpty(application.ProductUri)) {
                throw new ArgumentException(
                    "A ProductUri must be provided.", nameof(application.ProductUri));
            }

            if (!Uri.IsWellFormedUriString(application.ProductUri, UriKind.Absolute)) {
                throw new ArgumentException(application.ProductUri +
                    " is not a valid URI.", nameof(application.ProductUri));
            }

            if (application.DiscoveryUrls != null) {
                foreach (var discoveryUrl in application.DiscoveryUrls) {
                    if (string.IsNullOrEmpty(discoveryUrl)) {
                        continue;
                    }

                    if (!Uri.IsWellFormedUriString(discoveryUrl, UriKind.Absolute)) {
                        throw new ArgumentException(discoveryUrl + " is not a valid URL.",
                            nameof(application.DiscoveryUrls));
                    }

                    // TODO: check for https:/hostname:62541, typo is not detected here
                }
            }

            if ((int)application.ApplicationType != (int)Opc.Ua.ApplicationType.Client) {
                if (application.DiscoveryUrls == null || application.DiscoveryUrls.Length == 0) {
                    throw new ArgumentException(
                        "At least one DiscoveryUrl must be provided.",
                        nameof(application.DiscoveryUrls));
                }

                if (string.IsNullOrEmpty(application.ServerCapabilities)) {
                    throw new ArgumentException(
                        "At least one Server Capability must be provided.",
                        nameof(application.ServerCapabilities));
                }

                // TODO: check for valid servercapabilities
            }
            else {
                if (application.DiscoveryUrls != null && application.DiscoveryUrls.Length > 0) {
                    throw new ArgumentException(
                        "DiscoveryUrls must not be specified for clients.",
                        nameof(application.DiscoveryUrls));
                }
            }

            return application.ApplicationId;
        }

        /// <summary>
        /// Returns server capabilities as comma separated string.
        /// </summary>
        /// <param name="application">The application record.</param>
        public static string ServerCapabilities(ApplicationDocument application) {
            if ((int)application.ApplicationType != (int)ApplicationType.Client) {
                if (string.IsNullOrEmpty(application.ServerCapabilities)) {
                    throw new ArgumentException(
                        "At least one Server Capability must be provided.",
                        nameof(application.ServerCapabilities));
                }
            }

            var capabilities = new StringBuilder();
            if (application.ServerCapabilities != null) {
                var sortedCaps = application.ServerCapabilities.Split(",").ToList();
                sortedCaps.Sort();
                foreach (var capability in sortedCaps) {
                    if (string.IsNullOrEmpty(capability)) {
                        continue;
                    }

                    if (capabilities.Length > 0) {
                        capabilities.Append(',');
                    }

                    capabilities.Append(capability);
                }
            }

            return capabilities.ToString();
        }

        /// <summary>
        /// Convert the application Id string to Guid.
        /// Throws on invalid guid.
        /// </summary>
        /// <param name="applicationId"></param>
        private Guid ToGuidAndVerify(string applicationId) {
            try {
                if (string.IsNullOrEmpty(applicationId)) {
                    throw new ArgumentNullException(nameof(applicationId),
                        "The application id must be provided");
                }
                var guid = new Guid(applicationId);
                if (guid == Guid.Empty) {
                    throw new ArgumentException("The applicationId is invalid");
                }
                return guid;
            }
            catch (FormatException) {
                throw new ArgumentException("The applicationId is invalid.");
            }
        }

        /// <summary>
        /// Returns the next free, largest, application ID value.
        /// This is the ID value used for sorting in GDS queries.
        /// </summary>
        private async Task<int> GetMaxAppIDAsync() {
            try {
                // find new ID for QueryServers
                var sqlQuerySpec = new SqlQuerySpec {
                    QueryText = "SELECT TOP 1 * FROM Applications a WHERE a.ClassType = @classType ORDER BY a.ID DESC",
                    Parameters = new SqlParameterCollection { new SqlParameter("@classType", ApplicationDocument.ClassTypeName) }
                };
                var maxIDEnum = await _applications.GetAsync(sqlQuerySpec);
                var maxID = maxIDEnum.SingleOrDefault();
                return (maxID != null) ? maxID.ID + 1 : 1;
            }
            catch {
                return 1;
            }
        }

        private readonly IDocumentDBCollection<ApplicationDocument> _applications;
        private const int _defaultRecordsPerQuery = 10;
        private readonly ILogger _logger;
        private readonly bool _autoApprove;
        private readonly ILifetimeScope _scope;
        private int _appIdCounter = 1;
    }
}
