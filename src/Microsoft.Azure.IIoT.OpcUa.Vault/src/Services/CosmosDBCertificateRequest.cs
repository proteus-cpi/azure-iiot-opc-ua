// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace Microsoft.Azure.IIoT.OpcUa.Vault.Services {
    using Microsoft.Azure.IIoT.OpcUa.Vault.CosmosDB;
    using Microsoft.Azure.IIoT.OpcUa.Vault.CosmosDB.Services;
    using Microsoft.Azure.IIoT.OpcUa.Vault.Models;
    using Microsoft.Azure.IIoT.Exceptions;
    using Microsoft.Azure.Documents;
    using Microsoft.Azure.KeyVault.Models;
    using Microsoft.AspNetCore.Http;
    using Serilog;
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    using System.Text;
    using System.Threading.Tasks;
    using CertificateRequestDocument = CosmosDB.Models.CertificateRequestDocument;

    /// <summary>
    /// Cosmos db certificate request service
    /// </summary>
    public sealed class CosmosDBCertificateRequest : ICertificateRequest {

        /// <summary>
        /// Create certificate request
        /// </summary>
        /// <param name="database"></param>
        /// <param name="certificateGroup"></param>
        /// <param name="config"></param>
        /// <param name="db"></param>
        /// <param name="logger"></param>
        public CosmosDBCertificateRequest(IApplicationsDatabase database,
            ICertificateGroup certificateGroup, IVaultConfig config,
            IDocumentDBRepository db, ILogger logger) {

            _applicationsDatabase = database;
            _certificateGroup = certificateGroup;
            _logger = logger;
            _certificateRequests = new DocumentDBCollection<CertificateRequestDocument>(
                db, config.CosmosDBCollection);
            // set unique key in CosmosDB for Certificate ID ()
            // db.UniqueKeyPolicy.UniqueKeys.Add(new UniqueKey { Paths = new Collection<string> { "/" + nameof(CertificateRequest.ClassType), "/" + nameof(CertificateRequest.ID) } });
            _logger.Debug("Created new instance of `CosmosDBApplicationsDatabase` service " +
                config.CosmosDBCollection);
        }

        /// <inheritdoc/>
        public async Task InitializeAsync() {
            await _certificateRequests.CreateCollectionIfNotExistsAsync();
            _certRequestIdCounter = await GetMaxCertIdAsync();
        }

        /// <inheritdoc/>
        public async Task<ICertificateRequest> SendOnBehalfOfRequestAsync(HttpRequest request) {
            try {
                var onBehalfOfCertificateGroup =
                    await _certificateGroup.SendOnBehalfOfRequestAsync(request);
                var certRequest = (CosmosDBCertificateRequest)MemberwiseClone();
                certRequest._certificateGroup = onBehalfOfCertificateGroup;
                return certRequest;
            }
            catch (Exception ex) {
                // try default
                _logger.Error(ex, "Failed to create on behalf ICertificateRequest. ");
            }
            return this;
        }

        /// <inheritdoc/>
        public async Task<string> StartSigningRequestAsync(string applicationId,
            string certificateGroupId, string certificateTypeId, byte[] certificateSigningRequest,
            string authorityId) {
            var application = await _applicationsDatabase.GetApplicationAsync(applicationId);

            if (string.IsNullOrEmpty(certificateGroupId)) {
                //TODO:
            }
            if (string.IsNullOrEmpty(certificateTypeId)) {
                //TODO
            }
            var request = new CertificateRequestDocument {
                RequestId = Guid.NewGuid(),
                AuthorityId = authorityId,
                ID = _certRequestIdCounter++,
                CertificateRequestState = (int)CertificateRequestState.New,
                CertificateGroupId = certificateGroupId,
                CertificateTypeId = certificateTypeId,
                SubjectName = null,
                DomainNames = null,
                PrivateKeyFormat = null,
                PrivateKeyPassword = null,
                SigningRequest = certificateSigningRequest,
                ApplicationId = applicationId,
                RequestTime = DateTime.UtcNow
            };
            bool retry;
            do {
                retry = false;
                try {
                    var result = await _certificateRequests.CreateAsync(request);
                }
                catch (DocumentClientException dce) {
                    if (dce.StatusCode == System.Net.HttpStatusCode.Conflict) {
                        // retry with new guid and id
                        request.RequestId = Guid.NewGuid();
                        _certRequestIdCounter = await GetMaxCertIdAsync();
                        request.ID = _certRequestIdCounter++;
                        retry = true;
                    }
                }
            } while (retry);
            return request.RequestId.ToString();
        }

        /// <inheritdoc/>
        public async Task<string> StartNewKeyPairRequestAsync(string applicationId,
            string certificateGroupId, string certificateTypeId, string subjectName,
            IList<string> domainNames, string privateKeyFormat, string privateKeyPassword,
            string authorityId) {
            var application = await _applicationsDatabase.GetApplicationAsync(applicationId);

            if (string.IsNullOrEmpty(certificateGroupId)) {
                //TODO
            }

            if (string.IsNullOrEmpty(certificateTypeId)) {
                //TODO
            }

            if (string.IsNullOrEmpty(subjectName)) {
                throw new ArgumentNullException(nameof(subjectName));
            }

            var subjectList = Opc.Ua.Utils.ParseDistinguishedName(subjectName);
            if (subjectList == null ||
                subjectList.Count == 0) {
                throw new ArgumentException("Invalid Subject", nameof(subjectName));
            }

            if (!subjectList.Any(c => c.StartsWith("CN=", StringComparison.InvariantCulture))) {
                throw new ArgumentException("Invalid Subject, must have a common name (CN=).",
                    nameof(subjectName));
            }

            // enforce proper formatting for the subject name string
            subjectName = string.Join(", ", subjectList);
            var discoveryUrlDomainNames = new List<string>();
            if (domainNames != null) {
                foreach (var domainName in domainNames) {
                    if (!string.IsNullOrWhiteSpace(domainName)) {
                        var ipAddress = Opc.Ua.Utils.NormalizedIPAddress(domainName);
                        if (!string.IsNullOrEmpty(ipAddress)) {
                            discoveryUrlDomainNames.Add(ipAddress);
                        }
                        else {
                            discoveryUrlDomainNames.Add(domainName);
                        }
                    }
                }
            }
            else {
                discoveryUrlDomainNames = new List<string>();
            }
            if (application.DiscoveryUrls != null) {
                foreach (var discoveryUrl in application.DiscoveryUrls) {
                    var url = Opc.Ua.Utils.ParseUri(discoveryUrl);
                    if (url == null) {
                        continue;
                    }

                    var domainName = url.DnsSafeHost;
                    if (url.HostNameType != UriHostNameType.Dns) {
                        domainName = Opc.Ua.Utils.NormalizedIPAddress(domainName);
                    }
                    if (!Opc.Ua.Utils.FindStringIgnoreCase(discoveryUrlDomainNames, domainName)) {
                        discoveryUrlDomainNames.Add(domainName);
                    }
                }
            }

            var request = new CertificateRequestDocument {
                RequestId = Guid.NewGuid(),
                AuthorityId = authorityId,
                ID = _certRequestIdCounter++,
                CertificateRequestState = (int)CertificateRequestState.New,
                CertificateGroupId = certificateGroupId,
                CertificateTypeId = certificateTypeId,
                SubjectName = subjectName,
                DomainNames = discoveryUrlDomainNames.ToArray(),
                PrivateKeyFormat = privateKeyFormat,
                PrivateKeyPassword = privateKeyPassword,
                SigningRequest = null,
                ApplicationId = application.ApplicationId.ToString(),
                RequestTime = DateTime.UtcNow
            };
            bool retry;
            do {
                retry = false;
                try {
                    var result = await _certificateRequests.CreateAsync(request);
                }
                catch (DocumentClientException dce) {
                    if (dce.StatusCode == System.Net.HttpStatusCode.Conflict) {
                        // retry with new guid and id
                        request.RequestId = Guid.NewGuid();
                        _certRequestIdCounter = await GetMaxCertIdAsync();
                        request.ID = _certRequestIdCounter++;
                        retry = true;
                    }
                }
            } while (retry);

            return request.RequestId.ToString();
        }

        /// <inheritdoc/>
        public async Task ApproveAsync(string requestId, bool isRejected) {
            var reqId = GetIdFromString(requestId);
            bool retryUpdate;
            do {
                retryUpdate = false;
                var request = await _certificateRequests.GetAsync(reqId);

                if (request.CertificateRequestState != CertificateRequestState.New) {
                    throw new ResourceInvalidStateException(
                        "The record is not in a valid state for this operation.");
                }

                var application = await _applicationsDatabase.GetApplicationAsync(request.ApplicationId);

                if (isRejected) {
                    request.CertificateRequestState = CertificateRequestState.Rejected;
                    // erase information which is not required anymore
                    request.PrivateKeyFormat = null;
                    request.SigningRequest = null;
                    request.PrivateKeyPassword = null;
                }
                else {
                    request.CertificateRequestState = CertificateRequestState.Approved;

                    X509Certificate2 certificate;
                    if (request.SigningRequest != null) {
                        try {
                            certificate = await _certificateGroup.SigningRequestAsync(
                                request.CertificateGroupId,
                                application.ApplicationUri,
                                request.SigningRequest
                                );
                            request.Certificate = certificate.RawData;
                        }
                        catch (Exception e) {
                            var error = new StringBuilder();
                            error.Append("Error Generating Certificate=" + e.Message);
                            error.Append("\r\nApplicationId=" + application.ApplicationId);
                            error.Append("\r\nApplicationUri=" + application.ApplicationUri);
                            error.Append("\r\nApplicationName=" + application.ApplicationNames[0].Text);
                            throw new ResourceInvalidStateException(error.ToString());
                        }
                    }
                    else {
                        Opc.Ua.Gds.Server.X509Certificate2KeyPair newKeyPair = null;
                        try {
                            newKeyPair = await _certificateGroup.NewKeyPairRequestAsync(
                                request.CertificateGroupId,
                                requestId,
                                application.ApplicationUri,
                                request.SubjectName,
                                request.DomainNames,
                                request.PrivateKeyFormat,
                                request.PrivateKeyPassword);
                        }
                        catch (Exception e) {
                            var error = new StringBuilder();
                            error.Append("Error Generating New Key Pair Certificate=" + e.Message);
                            error.Append("\r\nApplicationId=" + application.ApplicationId);
                            error.Append("\r\nApplicationUri=" + application.ApplicationUri);
                            throw new ResourceInvalidStateException(error.ToString());
                        }
                        request.Certificate = newKeyPair.Certificate.RawData;
                        // ignore private key, it is stored in KeyVault
                    }
                }

                request.ApproveRejectTime = DateTime.UtcNow;
                try {
                    await _certificateRequests.UpdateAsync(reqId, request, request.ETag);
                }
                catch (DocumentClientException dce) {
                    if (dce.StatusCode == HttpStatusCode.PreconditionFailed) {
                        retryUpdate = true;
                    }
                }
            } while (retryUpdate);
        }

        /// <inheritdoc/>
        public async Task AcceptAsync(string requestId) {
            var reqId = GetIdFromString(requestId);
            bool retryUpdate;
            var first = true;
            do {
                retryUpdate = false;

                var request = await _certificateRequests.GetAsync(reqId);

                if (request.CertificateRequestState != CertificateRequestState.Approved) {
                    throw new ResourceInvalidStateException(
                        "The record is not in a valid state for this operation.");
                }

                if (request.PrivateKeyFormat != null && first) {
                    try {
                        await _certificateGroup.DeletePrivateKeyAsync(
                            request.CertificateGroupId, requestId);
                    }
                    catch (KeyVaultErrorException kex) {
                        if (kex.Response.StatusCode != HttpStatusCode.Forbidden) {
                            throw kex;
                        }
                        // ok to ignore, default KeyVault secret access 'Delete' is not granted.
                        // private key not deleted, must be handled by manager role
                    }
                }

                first = false;
                request.CertificateRequestState = CertificateRequestState.Accepted;

                // erase information which is not required anymore
                request.SigningRequest = null;
                request.PrivateKeyFormat = null;
                request.PrivateKeyPassword = null;
                request.AcceptTime = DateTime.UtcNow;
                try {
                    await _certificateRequests.UpdateAsync(request.RequestId, request, request.ETag);
                }
                catch (DocumentClientException dce) {
                    if (dce.StatusCode == HttpStatusCode.PreconditionFailed) {
                        retryUpdate = true;
                    }
                }
            } while (retryUpdate);
        }

        /// <inheritdoc/>
        public async Task DeleteAsync(string requestId) {
            var reqId = GetIdFromString(requestId);

            bool retryUpdate;
            var first = true;
            do {
                retryUpdate = false;
                var request = await _certificateRequests.GetAsync(reqId);

                var newStateRemoved =
                    request.CertificateRequestState == CertificateRequestState.New ||
                    request.CertificateRequestState == CertificateRequestState.Rejected;

                if (!newStateRemoved &&
                    request.CertificateRequestState != CertificateRequestState.Approved &&
                    request.CertificateRequestState != CertificateRequestState.Accepted) {
                    throw new ResourceInvalidStateException("The record is not in a valid state for this operation.");
                }

                request.CertificateRequestState = newStateRemoved ?
                    CertificateRequestState.Removed : CertificateRequestState.Deleted;
                // no need to delete pk for new & rejected requests
                if (!newStateRemoved && first &&
                    request.PrivateKeyFormat != null) {
                    try {
                        await _certificateGroup.DeletePrivateKeyAsync(request.CertificateGroupId, requestId);
                    }
                    catch (KeyVaultErrorException kex) {
                        if (kex.Response.StatusCode != HttpStatusCode.Forbidden) {
                            throw kex;
                        }
                        // ok to ignore, default KeyVault secret access 'Delete' is not granted.
                        // private key not deleted, must be handled by manager role
                    }
                }
                first = false;

                // erase information which is not required anymore
                request.SigningRequest = null;
                request.PrivateKeyFormat = null;
                request.PrivateKeyPassword = null;
                request.DeleteTime = DateTime.UtcNow;
                try {
                    await _certificateRequests.UpdateAsync(request.RequestId, request, request.ETag);
                }
                catch (DocumentClientException dce) {
                    if (dce.StatusCode == HttpStatusCode.PreconditionFailed) {
                        retryUpdate = true;
                    }
                }
            } while (retryUpdate);
        }

        /// <inheritdoc/>
        public async Task RevokeAsync(string requestId) {
            var reqId = GetIdFromString(requestId);

            bool retryUpdate;
            do {
                retryUpdate = false;
                var request = await _certificateRequests.GetAsync(reqId);

                if (request.Certificate == null ||
                    request.CertificateRequestState != CertificateRequestState.Deleted) {
                    throw new ResourceInvalidStateException("The record is not in a valid state for this operation.");
                }

                request.CertificateRequestState = CertificateRequestState.Revoked;
                // erase information which is not required anymore
                request.PrivateKeyFormat = null;
                request.SigningRequest = null;
                request.PrivateKeyPassword = null;

                try {
                    var cert = new X509Certificate2(request.Certificate);
                    var crl = await _certificateGroup.RevokeCertificateAsync(
                        request.CertificateGroupId, cert);
                }
                catch (Exception e) {
                    var error = new StringBuilder();
                    error.Append("Error Revoking Certificate=" + e.Message);
                    error.Append("\r\nGroupId=" + request.CertificateGroupId);
                    throw new ResourceInvalidStateException(error.ToString());
                }

                request.RevokeTime = DateTime.UtcNow;

                try {
                    await _certificateRequests.UpdateAsync(reqId, request, request.ETag);
                }
                catch (DocumentClientException dce) {
                    if (dce.StatusCode == HttpStatusCode.PreconditionFailed) {
                        retryUpdate = true;
                    }
                }
            } while (retryUpdate);
        }

        /// <inheritdoc/>
        public async Task PurgeAsync(string requestId) {
            var reqId = GetIdFromString(requestId);

            var request = await _certificateRequests.GetAsync(reqId);

            if (request.CertificateRequestState != CertificateRequestState.Revoked &&
                request.CertificateRequestState != CertificateRequestState.Rejected &&
                request.CertificateRequestState != CertificateRequestState.New &&
                request.CertificateRequestState != CertificateRequestState.Removed) {
                throw new ResourceInvalidStateException(
                    "The record is not in a valid state for this operation.");
            }

            await _certificateRequests.DeleteAsync(request.RequestId);
        }

        /// <inheritdoc/>
        public async Task RevokeGroupAsync(string groupId, bool? allVersions) {
            var queryParameters = new SqlParameterCollection();
            var query = "SELECT * FROM CertificateRequest r WHERE ";
            query += " r.CertificateRequestState = @state";
            queryParameters.Add(new SqlParameter("@state",
                CertificateRequestState.Deleted.ToString()));
            var sqlQuerySpec = new SqlQuerySpec {
                QueryText = query,
                Parameters = queryParameters
            };
            var deletedRequests = await _certificateRequests.GetAsync(sqlQuerySpec);
            if (deletedRequests == null || !deletedRequests.Any()) {
                return;
            }

            var revokedId = new List<Guid>();
            var certCollection = new X509Certificate2Collection();
            foreach (var request in deletedRequests) {
                if (request.Certificate != null) {
                    if (string.Compare(request.CertificateGroupId, groupId,
                        StringComparison.OrdinalIgnoreCase) == 0) {
                        try {
                            var cert = new X509Certificate2(request.Certificate);
                            certCollection.Add(cert);
                            revokedId.Add(request.RequestId);
                        }
#pragma warning disable RECS0022 // A catch clause that catches System.Exception and has an empty body
                        catch {
#pragma warning restore RECS0022 // A catch clause that catches System.Exception and has an empty body
                            // skip
                        }
                    }
                }
            }

            var remainingCertificates = await _certificateGroup.RevokeCertificatesAsync(
                groupId, certCollection);
            foreach (var reqId in deletedRequests) {
                bool retryUpdate;
                do {
                    retryUpdate = false;
                    var request = await _certificateRequests.GetAsync(reqId.RequestId);

                    if (request.CertificateRequestState != CertificateRequestState.Deleted) {
                        // skip, there may have been a concurrent update to the database.
                        continue;
                    }

                    // TODO: test for remaining certificates

                    request.CertificateRequestState = CertificateRequestState.Revoked;
                    request.RevokeTime = DateTime.UtcNow;
                    // erase information which is not required anymore
                    request.Certificate = null;
                    request.PrivateKeyFormat = null;
                    request.SigningRequest = null;
                    request.PrivateKeyPassword = null;

                    try {
                        await _certificateRequests.UpdateAsync(reqId.RequestId, request, request.ETag);
                    }
                    catch (DocumentClientException dce) {
                        if (dce.StatusCode == HttpStatusCode.PreconditionFailed) {
                            retryUpdate = true;
                        }
                    }
                } while (retryUpdate);
            }
        }

        /// <inheritdoc/>
        public async Task<FetchRequestResultModel> FetchRequestAsync(string requestId,
            string applicationId) {
            var reqId = GetIdFromString(requestId);
            var application = await _applicationsDatabase.GetApplicationAsync(applicationId);
            var request = await _certificateRequests.GetAsync(reqId);
            if (request.ApplicationId != application.ApplicationId.ToString()) {
                throw new ArgumentException("The recordId does not match the applicationId.");
            }

            switch (request.CertificateRequestState) {
                case CertificateRequestState.New:
                case CertificateRequestState.Rejected:
                case CertificateRequestState.Revoked:
                case CertificateRequestState.Deleted:
                case CertificateRequestState.Removed:
                    return new FetchRequestResultModel(request.CertificateRequestState) {
                        ApplicationId = applicationId,
                        RequestId = requestId
                    };
                case CertificateRequestState.Accepted:
                case CertificateRequestState.Approved:
                    break;
                default:
                    throw new ResourceInvalidStateException("The record is not in a valid state for this operation.");
            }

            // get private key
            byte[] privateKey = null;
            if (request.CertificateRequestState == CertificateRequestState.Approved &&
                request.PrivateKeyFormat != null) {
                try {
                    privateKey = await _certificateGroup.LoadPrivateKeyAsync(
                        request.CertificateGroupId, requestId, request.PrivateKeyFormat);
                }
                catch {
                    // intentionally ignore error when reading private key
                    // it may have been disabled by keyvault due to inactivity...
                    request.PrivateKeyFormat = null;
                    privateKey = null;
                }
            }

            return new FetchRequestResultModel(request.CertificateRequestState,
                applicationId, requestId, request.CertificateGroupId,
                request.CertificateTypeId, request.Certificate,
                request.PrivateKeyFormat, privateKey, request.AuthorityId);
        }

        /// <inheritdoc/>
        public async Task<ReadRequestResultModel> ReadAsync(string requestId) {
            var reqId = GetIdFromString(requestId);
            var request = await _certificateRequests.GetAsync(reqId);
            switch (request.CertificateRequestState) {
                case CertificateRequestState.New:
                case CertificateRequestState.Rejected:
                case CertificateRequestState.Accepted:
                case CertificateRequestState.Approved:
                case CertificateRequestState.Deleted:
                case CertificateRequestState.Revoked:
                case CertificateRequestState.Removed:
                    break;
                default:
                    throw new ResourceInvalidStateException(
                        "The record is not in a valid state for this operation.");
            }
            return new ReadRequestResultModel(requestId, request.ApplicationId,
                request.CertificateRequestState, request.CertificateGroupId,
                request.CertificateTypeId, request.SigningRequest,
                request.SubjectName, request.DomainNames, request.PrivateKeyFormat);

        }

        /// <inheritdoc/>
        public async Task<(string, ReadRequestResultModel[])> QueryPageAsync(string appId,
            CertificateRequestState? state, string nextPageLink, int? maxResults) {
            IEnumerable<CertificateRequestDocument> requests;
            var queryParameters = new SqlParameterCollection();
            var query = "SELECT * FROM CertificateRequest r WHERE ";
            if (appId == null && state == null) {
                query += " r.CertificateRequestState != @state";
                queryParameters.Add(new SqlParameter("@state", CertificateRequestState.Deleted.ToString()));
            }
            else if (appId != null && state != null) {
                query += " r.ApplicationId = @appId AND r.CertificateRequestState = @state ";
                queryParameters.Add(new SqlParameter("@appId", appId));
                queryParameters.Add(new SqlParameter("@state", state.ToString()));
            }
            else if (appId != null) {
                query += " r.ApplicationId = @appId";
                queryParameters.Add(new SqlParameter("@appId", appId));
            }
            else {
                query += " r.CertificateRequestState = @state ";
                queryParameters.Add(new SqlParameter("@state", state.ToString()));
            }
            var sqlQuerySpec = new SqlQuerySpec {
                QueryText = query,
                Parameters = queryParameters
            };
            (nextPageLink, requests) = await _certificateRequests.GetPageAsync(
                sqlQuerySpec, nextPageLink, maxResults);
            var result = new List<ReadRequestResultModel>();
            foreach (var request in requests) {
                result.Add(new ReadRequestResultModel(request));
            }
            return (nextPageLink, result.ToArray());
        }

        /// <summary>
        /// Get max cert id
        /// </summary>
        /// <returns></returns>
        private async Task<int> GetMaxCertIdAsync() {
            try {
                // find new ID for QueryServers
                var sqlQuerySpec = new SqlQuerySpec {
                    QueryText = "SELECT TOP 1 * FROM Applications a WHERE a.ClassType = @classType ORDER BY a.ID DESC",
                    Parameters = new SqlParameterCollection {
                        new SqlParameter("@classType", CertificateRequestDocument.ClassTypeName)
                    }
                };
                var maxIDEnum = await _certificateRequests.GetAsync(sqlQuerySpec);
                var maxID = maxIDEnum.SingleOrDefault();
                return (maxID != null) ? maxID.ID + 1 : 1;
            }
            catch {
                return 1;
            }
        }

        /// <summary>
        /// Get id from string
        /// </summary>
        /// <param name="requestId"></param>
        /// <returns></returns>
        private Guid GetIdFromString(string requestId) {
            try {
                if (string.IsNullOrEmpty(requestId)) {
                    throw new ArgumentNullException(nameof(requestId), "The request id must be provided");
                }
                var guidId = new Guid(requestId);
                if (guidId == Guid.Empty) {
                    throw new ArgumentException("The id must be provided.", nameof(requestId));
                }
                return guidId;
            }
            catch (FormatException) {
                throw new ArgumentException("The requestId is invalid.");
            }
        }

        internal IApplicationsDatabase _applicationsDatabase;
        internal ICertificateGroup _certificateGroup;
        private readonly ILogger _logger;
        private int _certRequestIdCounter = 1;
        private readonly IDocumentDBCollection<CertificateRequestDocument> _certificateRequests;
    }
}
