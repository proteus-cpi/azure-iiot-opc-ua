// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace Microsoft.Azure.IIoT.OpcUa.Vault.Services {
    using Microsoft.Azure.IIoT.OpcUa.Vault.CosmosDB;
    using Microsoft.Azure.IIoT.OpcUa.Vault.CosmosDB.Models;
    using Microsoft.Azure.IIoT.OpcUa.Vault.CosmosDB.Services;
    using Microsoft.Azure.IIoT.OpcUa.Vault.Models;
    using Microsoft.Azure.IIoT.Exceptions;
    using Microsoft.Azure.Documents;
    using Microsoft.Azure.KeyVault.Models;
    using Serilog;
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    using System.Text;
    using System.Threading.Tasks;

    /// <summary>
    /// Cosmos db certificate request service
    /// </summary>
    public sealed class DefaultCertificateAuthority : ICertificateAuthority {

        /// <summary>
        /// Create certificate request
        /// </summary>
        /// <param name="database"></param>
        /// <param name="vaultClient"></param>
        /// <param name="config"></param>
        /// <param name="db"></param>
        /// <param name="logger"></param>
        public DefaultCertificateAuthority(IApplicationsDatabase database,
            IVaultClient vaultClient, IVaultConfig config, IDocumentDBRepository db,
            ILogger logger) {

            _applicationsDatabase = database;
            _vaultClient = vaultClient;
            _logger = logger;
            _certificateRequests = new DocumentDBCollection<CertificateRequestDocument>(
                db, config.CollectionName);
            // set unique key
            db.UniqueKeyPolicy.UniqueKeys.Add(new UniqueKey {
                Paths = new System.Collections.ObjectModel.Collection<string> {
                    "/" + nameof(CertificateRequestDocument.ClassType),
                    "/" + nameof(CertificateRequestDocument.ID)
                }
            });
            _logger.Debug("Created new instance of DefaultCertificateAuthority.");
        }

        /// <inheritdoc/>
        public async Task InitializeAsync() {
            await _certificateRequests.CreateCollectionIfNotExistsAsync();
            _certRequestIdCounter = await GetMaxCertIdAsync();
        }

        /// <inheritdoc/>
        public async Task<string> StartSigningRequestAsync(
            CreateSigningRequestModel request, string authorityId) {
            if (request == null) {
                throw new ArgumentNullException(nameof(request));
            }
            if (string.IsNullOrEmpty(request.ApplicationId)) {
                throw new ArgumentNullException(nameof(request.ApplicationId));
            }
            if (string.IsNullOrEmpty(request.CertificateGroupId)) {
                //TODO:
            }
            if (string.IsNullOrEmpty(request.CertificateTypeId)) {
                //TODO
            }
            var application = await _applicationsDatabase.GetApplicationAsync(
                request.ApplicationId);
            var document = new CertificateRequestDocument {
                RequestId = Guid.NewGuid().ToString(),
                AuthorityId = authorityId,
                ID = _certRequestIdCounter++,
                CertificateRequestState = (int)CertificateRequestState.New,
                CertificateGroupId = request.CertificateGroupId,
                CertificateTypeId = request.CertificateTypeId,
                SubjectName = null,
                DomainNames = null,
                PrivateKeyFormat = null,
                PrivateKeyPassword = null,
                SigningRequest = request.ToRawData(),
                ApplicationId = request.ApplicationId,
                RequestTime = DateTime.UtcNow
            };
            bool retry;
            do {
                retry = false;
                try {
                    var result = await _certificateRequests.CreateAsync(document);
                }
                catch (DocumentClientException dce) {
                    if (dce.StatusCode == HttpStatusCode.Conflict) {
                        // retry with new guid and id
                        document.RequestId = Guid.NewGuid().ToString();
                        _certRequestIdCounter = await GetMaxCertIdAsync();
                        document.ID = _certRequestIdCounter++;
                        retry = true;
                    }
                }
            } while (retry);
            return document.RequestId;
        }

        /// <inheritdoc/>
        public async Task<string> StartNewKeyPairRequestAsync(
            CreateNewKeyPairRequestModel request, string authorityId) {

            if (request == null) {
                throw new ArgumentNullException(nameof(request));
            }
            if (string.IsNullOrEmpty(request.ApplicationId)) {
                throw new ArgumentNullException(nameof(request.ApplicationId));
            }
            if (string.IsNullOrEmpty(request.CertificateGroupId)) {
                //TODO
            }
            if (string.IsNullOrEmpty(request.CertificateTypeId)) {
                //TODO
            }
            if (string.IsNullOrEmpty(request.SubjectName)) {
                throw new ArgumentNullException(nameof(request.SubjectName));
            }

            var subjectList = Opc.Ua.Utils.ParseDistinguishedName(request.SubjectName);
            if (subjectList == null ||
                subjectList.Count == 0) {
                throw new ArgumentException("Invalid Subject", nameof(request.SubjectName));
            }
            if (!subjectList.Any(c => c.StartsWith("CN=", StringComparison.InvariantCulture))) {
                throw new ArgumentException("Invalid Subject, must have a common name (CN=).",
                    nameof(request.SubjectName));
            }
            // enforce proper formatting for the subject name string
            var subjectName = string.Join(", ", subjectList);
            var discoveryUrlDomainNames = new List<string>();
            if (request.DomainNames != null) {
                foreach (var domainName in request.DomainNames) {
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

            var application = await _applicationsDatabase.GetApplicationAsync(request.ApplicationId);
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

            var document = new CertificateRequestDocument {
                RequestId = Guid.NewGuid().ToString(),
                AuthorityId = authorityId,
                ID = _certRequestIdCounter++,
                CertificateRequestState = (int)CertificateRequestState.New,
                CertificateGroupId = request.CertificateGroupId,
                CertificateTypeId = request.CertificateTypeId,
                SubjectName = subjectName,
                DomainNames = discoveryUrlDomainNames.ToArray(),
                PrivateKeyFormat = request.PrivateKeyFormat,
                PrivateKeyPassword = request.PrivateKeyPassword,
                SigningRequest = null,
                ApplicationId = application.ApplicationId,
                RequestTime = DateTime.UtcNow
            };
            bool retry;
            do {
                retry = false;
                try {
                    var result = await _certificateRequests.CreateAsync(document);
                }
                catch (DocumentClientException dce) {
                    if (dce.StatusCode == HttpStatusCode.Conflict) {
                        // retry with new guid and id
                        document.RequestId = Guid.NewGuid().ToString();
                        _certRequestIdCounter = await GetMaxCertIdAsync();
                        document.ID = _certRequestIdCounter++;
                        retry = true;
                    }
                }
            } while (retry);
            return document.RequestId;
        }

        /// <inheritdoc/>
        public async Task ApproveAsync(string requestId) {
            if (string.IsNullOrEmpty(requestId)) {
                throw new ArgumentNullException(nameof(requestId), "The request id must be provided");
            }
            bool retryUpdate;
            do {
                retryUpdate = false;
                var request = await _certificateRequests.GetAsync(requestId);

                if (request.CertificateRequestState != CertificateRequestState.New) {
                    throw new ResourceInvalidStateException(
                        "The record is not in a valid state for this operation.");
                }

                var application = await _applicationsDatabase.GetApplicationAsync(
                    request.ApplicationId);
                request.CertificateRequestState = CertificateRequestState.Approved;
                X509CertificateModel certificate;
                if (request.SigningRequest != null) {
                    try {
                        certificate = await _vaultClient.SigningRequestAsync(
                            request.CertificateGroupId, application.ApplicationUri,
                            request.SigningRequest);
                        request.Certificate = certificate.ToRawData();
                    }
                    catch (Exception e) {
                        var error = new StringBuilder();
                        error.Append("Error Generating Certificate=" + e.Message);
                        error.Append("\r\nApplicationId=" + application.ApplicationId);
                        error.Append("\r\nApplicationUri=" + application.ApplicationUri);
                        error.Append("\r\nApplicationName=" + application.ApplicationName);
                        throw new ResourceInvalidStateException(error.ToString());
                    }
                }
                else {
                    X509CertificatePrivateKeyPairModel newKeyPair;
                    try {
                        newKeyPair = await _vaultClient.NewKeyPairRequestAsync(
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
                        error.Append("\r\nApplicationName=" + application.ApplicationName);
                        throw new ResourceInvalidStateException(error.ToString());
                    }
                    request.Certificate = newKeyPair.Certificate.ToRawData();
                    // ignore private key, it is stored in KeyVault
                }

                request.ApproveRejectTime = DateTime.UtcNow;
                try {
                    await _certificateRequests.UpdateAsync(requestId, request, request.ETag);
                }
                catch (DocumentClientException dce) {
                    if (dce.StatusCode == HttpStatusCode.PreconditionFailed) {
                        retryUpdate = true;
                    }
                }
            } while (retryUpdate);
        }

        /// <inheritdoc/>
        public async Task RejectAsync(string requestId) {
            if (string.IsNullOrEmpty(requestId)) {
                throw new ArgumentNullException(nameof(requestId), "The request id must be provided");
            }
            bool retryUpdate;
            do {
                retryUpdate = false;
                var request = await _certificateRequests.GetAsync(requestId);

                if (request.CertificateRequestState != CertificateRequestState.New) {
                    throw new ResourceInvalidStateException(
                        "The record is not in a valid state for this operation.");
                }

                var application = await _applicationsDatabase.GetApplicationAsync(request.ApplicationId);

                request.CertificateRequestState = CertificateRequestState.Rejected;
                // erase information which is not required anymore
                request.PrivateKeyFormat = null;
                request.SigningRequest = null;
                request.PrivateKeyPassword = null;
                request.ApproveRejectTime = DateTime.UtcNow;
                try {
                    await _certificateRequests.UpdateAsync(requestId, request, request.ETag);
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
            if (string.IsNullOrEmpty(requestId)) {
                throw new ArgumentNullException(nameof(requestId), "The request id must be provided");
            }
            bool retryUpdate;
            var first = true;
            do {
                retryUpdate = false;

                var request = await _certificateRequests.GetAsync(requestId);

                if (request.CertificateRequestState != CertificateRequestState.Approved) {
                    throw new ResourceInvalidStateException(
                        "The record is not in a valid state for this operation.");
                }

                if (request.PrivateKeyFormat != null && first) {
                    try {
                        await _vaultClient.DeletePrivateKeyAsync(
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
            if (string.IsNullOrEmpty(requestId)) {
                throw new ArgumentNullException(nameof(requestId), "The request id must be provided");
            }
            bool retryUpdate;
            var first = true;
            do {
                retryUpdate = false;
                var request = await _certificateRequests.GetAsync(requestId);

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
                        await _vaultClient.DeletePrivateKeyAsync(request.CertificateGroupId, requestId);
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
                    await _certificateRequests.UpdateAsync(request.RequestId,
                        request, request.ETag);
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
            if (string.IsNullOrEmpty(requestId)) {
                throw new ArgumentNullException(nameof(requestId), "The request id must be provided");
            }
            bool retryUpdate;
            do {
                retryUpdate = false;
                var request = await _certificateRequests.GetAsync(requestId);

                if (request.Certificate == null ||
                    request.CertificateRequestState != CertificateRequestState.Deleted) {
                    throw new ResourceInvalidStateException(
                        "The record is not in a valid state for this operation.");
                }

                request.CertificateRequestState = CertificateRequestState.Revoked;
                // erase information which is not required anymore
                request.PrivateKeyFormat = null;
                request.SigningRequest = null;
                request.PrivateKeyPassword = null;

                try {
                    var cert = new X509Certificate2(request.Certificate).ToServiceModel();
                    var crl = await _vaultClient.RevokeCertificateAsync(
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
                    await _certificateRequests.UpdateAsync(requestId, request, request.ETag);
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
            if (string.IsNullOrEmpty(requestId)) {
                throw new ArgumentNullException(nameof(requestId), "The request id must be provided");
            }
            var request = await _certificateRequests.GetAsync(requestId);

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

            var revokedId = new List<string>();
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

            var remainingCertificates = await _vaultClient.RevokeCertificatesAsync(
                groupId, certCollection.ToServiceModel(null));
            foreach (var requestId in deletedRequests) {
                bool retryUpdate;
                do {
                    retryUpdate = false;
                    var request = await _certificateRequests.GetAsync(requestId.RequestId);

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
                        await _certificateRequests.UpdateAsync(requestId.RequestId, request, request.ETag);
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
        public async Task<FetchCertificateRequestResultModel> FetchRequestAsync(string requestId,
            string applicationId) {
            if (string.IsNullOrEmpty(requestId)) {
                throw new ArgumentNullException(nameof(requestId), "The request id must be provided");
            }
            var application = await _applicationsDatabase.GetApplicationAsync(applicationId);
            var request = await _certificateRequests.GetAsync(requestId);
            if (request.ApplicationId != application.ApplicationId.ToString()) {
                throw new ArgumentException("The recordId does not match the applicationId.");
            }

            switch (request.CertificateRequestState) {
                case CertificateRequestState.New:
                case CertificateRequestState.Rejected:
                case CertificateRequestState.Revoked:
                case CertificateRequestState.Deleted:
                case CertificateRequestState.Removed:
                    return new FetchCertificateRequestResultModel {
                        State = request.CertificateRequestState,
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
                    privateKey = await _vaultClient.LoadPrivateKeyAsync(
                        request.CertificateGroupId, requestId, request.PrivateKeyFormat);
                }
                catch {
                    // intentionally ignore error when reading private key
                    // it may have been disabled by keyvault due to inactivity...
                    request.PrivateKeyFormat = null;
                    privateKey = null;
                }
            }
            return new FetchCertificateRequestResultModel {
                State = request.CertificateRequestState,
                ApplicationId = applicationId,
                RequestId = requestId,
                CertificateGroupId = request.CertificateGroupId,
                CertificateTypeId = request.CertificateTypeId,
                SignedCertificate = request.Certificate,
                PrivateKeyFormat = request.PrivateKeyFormat,
                PrivateKey = privateKey,
                AuthorityId = request.AuthorityId
            };
        }

        /// <inheritdoc/>
        public async Task<CertificateRequestRecordModel> ReadAsync(string requestId) {
            if (string.IsNullOrEmpty(requestId)) {
                throw new ArgumentNullException(nameof(requestId), "The request id must be provided");
            }
            var request = await _certificateRequests.GetAsync(requestId);
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
            return new CertificateRequestRecordModel {
                RequestId = requestId,
                ApplicationId = request.ApplicationId,
                State = request.CertificateRequestState,
                CertificateGroupId = request.CertificateGroupId,
                CertificateTypeId = request.CertificateTypeId,
                SigningRequest = request.SigningRequest != null,
                SubjectName = request.SubjectName,
                DomainNames = request.DomainNames,
                PrivateKeyFormat = request.PrivateKeyFormat
            };
        }

        /// <inheritdoc/>
        public async Task<CertificateRequestQueryResultModel> QueryPageAsync(string appId,
            CertificateRequestState? state, string nextPageLink, int? maxResults) {
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
            var (nextLink, requests) = await _certificateRequests.GetPageAsync(
                sqlQuerySpec, nextPageLink, maxResults);
            return new CertificateRequestQueryResultModel {
                NextPageLink = nextLink,
                Requests = requests.Select(r => r.ToServiceModel()).ToList()
            };
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

        internal IApplicationsDatabase _applicationsDatabase;
        internal IVaultClient _vaultClient;
        private int _certRequestIdCounter = 1;
        private readonly ILogger _logger;
        private readonly IDocumentDBCollection<CertificateRequestDocument> _certificateRequests;
    }
}
