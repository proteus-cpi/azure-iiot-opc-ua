// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace Microsoft.Azure.IIoT.OpcUa.Vault.Services {
    using Microsoft.Azure.IIoT.OpcUa.Vault.Services.CosmosDB;
    using Microsoft.Azure.IIoT.OpcUa.Vault.Services.CosmosDB.Models;
    using Microsoft.Azure.IIoT.OpcUa.Vault.Services.CosmosDB.Services;
    using Microsoft.Azure.IIoT.OpcUa.Vault.Models;
    using Microsoft.Azure.IIoT.OpcUa.Vault;
    using Microsoft.Azure.IIoT.OpcUa.Registry;
    using Microsoft.Azure.IIoT.OpcUa.Registry.Models;
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
    using Autofac;
    using Microsoft.Azure.IIoT.Storage;

    /// <summary>
    /// Cosmos db certificate request management workflow service
    /// </summary>
    public sealed class CertificateAuthority : ICertificateAuthority {

        /// <summary>
        /// Create certificate request
        /// </summary>
        /// <param name="database"></param>
        /// <param name="vaultClient"></param>
        /// <param name="db"></param>
        /// <param name="logger"></param>
        public CertificateAuthority(IApplicationRegistry database,
            ICertificateStorage vaultClient, IItemContainerFactory db,
            ILogger logger) {

            _applicationsDatabase = database;
            _vaultClient = vaultClient;
            _logger = logger;
            _certificateRequests = db.OpenAsync().Result.AsDocuments();
        //   // set unique key
        //   db.UniqueKeyPolicy.UniqueKeys.Add(new UniqueKey {
        //       Paths = new System.Collections.ObjectModel.Collection<string> {
        //           "/" + nameof(CertificateRequestDocument.ClassType),
        //           "/" + nameof(CertificateRequestDocument.ID)
        //       }
        //   });
        }

        /// <inheritdoc/>
        public async Task<string> SubmitSigningRequestAsync(
            SigningRequestModel request, string authorityId) {
            if (request == null) {
                throw new ArgumentNullException(nameof(request));
            }
            if (string.IsNullOrEmpty(request.ApplicationId)) {
                throw new ArgumentNullException(nameof(request.ApplicationId));
            }
            if (string.IsNullOrEmpty(request.CertificateGroupId)) {
                //TODO:
            }
            var application = await _applicationsDatabase.GetApplicationAsync(
                request.ApplicationId);
            while (true) {
                var document = new CertificateRequestDocument {
                    RequestId = Guid.NewGuid().ToString(),
                    AuthorityId = authorityId,
                    ID = await GetNextRecordIdAsync(),
                    CertificateRequestState = (int)CertificateRequestState.New,
                    CertificateGroupId = request.CertificateGroupId,
                    CertificateTypeId = request.CertificateTypeId.ToString(),
                    SubjectName = null,
                    DomainNames = null,
                    PrivateKeyFormat = null,
                    PrivateKeyPassword = null,
                    SigningRequest = request.ToRawData(),
                    ApplicationId = request.ApplicationId,
                    RequestTime = DateTime.UtcNow
                };
                try {
                    var result = await _certificateRequests.AddAsync(document);
                    return result.Value.RequestId;
                }
                catch (ConflictingResourceException) {
                    continue;
                }
            } 
        }

        /// <inheritdoc/>
        public async Task<string> SubmitNewKeyPairRequestAsync(
            NewKeyPairRequestModel request, string authorityId) {

            if (request == null) {
                throw new ArgumentNullException(nameof(request));
            }
            if (string.IsNullOrEmpty(request.ApplicationId)) {
                throw new ArgumentNullException(nameof(request.ApplicationId));
            }
            if (string.IsNullOrEmpty(request.CertificateGroupId)) {
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

            var registration = await _applicationsDatabase.GetApplicationAsync(
                request.ApplicationId);
            if (registration.Application.DiscoveryUrls != null) {
                foreach (var discoveryUrl in registration.Application.DiscoveryUrls) {
                    var url = Opc.Ua.Utils.ParseUri(discoveryUrl);
                    if (url == null) {
                        continue;
                    }
                    var domainName = url.DnsSafeHost;
                    if (url.HostNameType != UriHostNameType.Dns) {
                        domainName = Opc.Ua.Utils.NormalizedIPAddress(domainName);
                    }
                    if (!Opc.Ua.Utils.FindStringIgnoreCase(discoveryUrlDomainNames,
                        domainName)) {
                        discoveryUrlDomainNames.Add(domainName);
                    }
                }
            }

            while (true) {
                var document = new CertificateRequestDocument {
                    RequestId = Guid.NewGuid().ToString(),
                    AuthorityId = authorityId,
                    ID = await GetNextRecordIdAsync(),
                    CertificateRequestState = (int)CertificateRequestState.New,
                    CertificateGroupId = request.CertificateGroupId,
                    CertificateTypeId = request.CertificateTypeId.ToString(),
                    SubjectName = subjectName,
                    DomainNames = discoveryUrlDomainNames.ToArray(),
                    PrivateKeyFormat = request.PrivateKeyFormat.ToString(),
                    PrivateKeyPassword = request.PrivateKeyPassword,
                    SigningRequest = null,
                    ApplicationId = registration.Application.ApplicationId,
                    RequestTime = DateTime.UtcNow
                };
                try {
                    var result = await _certificateRequests.AddAsync(document);
                    return result.Value.RequestId;
                }
                catch (ConflictingResourceException) {
                    continue;
                }
            }
        }

        /// <inheritdoc/>
        public async Task ApproveRequestAsync(string requestId) {
            if (string.IsNullOrEmpty(requestId)) {
                throw new ArgumentNullException(nameof(requestId),
                    "The request id must be provided");
            }
            while (true) {
                var request = await _certificateRequests.GetAsync<CertificateRequestDocument>(
                    requestId);
                if (request == null) {
                    throw new ResourceNotFoundException("Request not found");
                }
                if (request.Value.CertificateRequestState != CertificateRequestState.New) {
                    throw new ResourceInvalidStateException(
                        "The record is not in a valid state for this operation.");
                }

                var registration = await _applicationsDatabase.GetApplicationAsync(
                request.Value.ApplicationId);
                request.Value.CertificateRequestState = CertificateRequestState.Approved;
                X509CertificateModel certificate;
                if (request.Value.SigningRequest != null) {
                    try {
                        certificate = await _vaultClient.ProcessSigningRequestAsync(
                            request.Value.CertificateGroupId, registration.Application.ApplicationUri,
                            request.Value.SigningRequest);
                        request.Value.Certificate = certificate.ToRawData();
                    }
                    catch (Exception e) {
                        var error = new StringBuilder();
                        error.Append("Error Generating Certificate=" + e.Message);
                        error.Append("\r\nApplicationId=" +
                            registration.Application.ApplicationId);
                        error.Append("\r\nApplicationUri=" +
                            registration.Application.ApplicationUri);
                        error.Append("\r\nApplicationName=" +
                            registration.Application.ApplicationName);
                        throw new ResourceInvalidStateException(error.ToString());
                    }
                }
                else {
                    X509CertificatePrivateKeyPairModel newKeyPair;
                    try {
                        newKeyPair = await _vaultClient.ProcessNewKeyPairRequestAsync(
                            request.Value.CertificateGroupId,
                            requestId,
                            registration.Application.ApplicationUri,
                            request.Value.SubjectName,
                            request.Value.DomainNames,
                            request.Value.PrivateKeyFormat,
                            request.Value.PrivateKeyPassword);
                    }
                    catch (Exception e) {
                        var error = new StringBuilder();
                        error.Append("Error Generating New Key Pair Certificate=" + e.Message);
                        error.Append("\r\nApplicationId=" +
                            registration.Application.ApplicationId);
                        error.Append("\r\nApplicationUri=" +
                            registration.Application.ApplicationUri);
                        error.Append("\r\nApplicationName=" +
                            registration.Application.ApplicationName);
                        throw new ResourceInvalidStateException(error.ToString());
                    }
                    request.Value.Certificate = newKeyPair.Certificate.ToRawData();
                    // ignore private key, it is stored in KeyVault
                }

                request.Value.ApproveRejectTime = DateTime.UtcNow;
                try {
                    await _certificateRequests.ReplaceAsync(request, request.Value);
                }
                catch (ResourceOutOfDateException) {
                    continue;
                }
                break;
            }
        }

        /// <inheritdoc/>
        public async Task RejectRequestAsync(string requestId) {
            if (string.IsNullOrEmpty(requestId)) {
                throw new ArgumentNullException(nameof(requestId), "The request id must be provided");
            }
            while (true) {
                var request = await _certificateRequests.GetAsync<CertificateRequestDocument>(
                    requestId);
                if (request == null) {
                    throw new ResourceNotFoundException("Request not found");
                }
                if (request.Value.CertificateRequestState != CertificateRequestState.New) {
                    throw new ResourceInvalidStateException(
                        "The record is not in a valid state for this operation.");
                }

                var application = await _applicationsDatabase.GetApplicationAsync(
                    request.Value.ApplicationId);

                request.Value.CertificateRequestState = CertificateRequestState.Rejected;
                // erase information which is not required anymore
                request.Value.PrivateKeyFormat = null;
                request.Value.SigningRequest = null;
                request.Value.PrivateKeyPassword = null;
                request.Value.ApproveRejectTime = DateTime.UtcNow;

                try {
                    await _certificateRequests.ReplaceAsync(request, request.Value);
                }
                catch (ResourceOutOfDateException) {
                    continue;
                }
                break;
            }
        }

        /// <inheritdoc/>
        public async Task AcceptRequestAsync(string requestId) {
            if (string.IsNullOrEmpty(requestId)) {
                throw new ArgumentNullException(nameof(requestId),
                    "The request id must be provided");
            }
            var first = true;
            while (true) {
                var request = await _certificateRequests.GetAsync<CertificateRequestDocument>(
                    requestId);
                if (request == null) {
                    throw new ResourceNotFoundException("Request not found");
                }

                if (request.Value.CertificateRequestState != CertificateRequestState.Approved) {
                    throw new ResourceInvalidStateException(
                        "The record is not in a valid state for this operation.");
                }


                if (request.Value.PrivateKeyFormat != null && first) {
                    try {
                        await _vaultClient.DeletePrivateKeyAsync(
                            request.Value.CertificateGroupId, requestId);
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

                request.Value.CertificateRequestState = CertificateRequestState.Accepted;
                // erase information which is not required anymore
                request.Value.SigningRequest = null;
                request.Value.PrivateKeyFormat = null;
                request.Value.PrivateKeyPassword = null;
                request.Value.AcceptTime = DateTime.UtcNow;
                try {
                    await _certificateRequests.ReplaceAsync(request, request.Value);
                }
                catch (ResourceOutOfDateException) {
                    continue;
                }
                break;
            }
        }

        /// <inheritdoc/>
        public async Task DeleteRequestAsync(string requestId) {
            if (string.IsNullOrEmpty(requestId)) {
                throw new ArgumentNullException(nameof(requestId), "The request id must be provided");
            }
            var first = true;
            while (true) {
                var request = await _certificateRequests.GetAsync<CertificateRequestDocument>(
                    requestId);
                if (request == null) {
                    throw new ResourceNotFoundException("Request not found");
                }

                var newStateRemoved =
                    request.Value.CertificateRequestState == CertificateRequestState.New ||
                    request.Value.CertificateRequestState == CertificateRequestState.Rejected;

                if (!newStateRemoved &&
                    request.Value.CertificateRequestState != CertificateRequestState.Approved &&
                    request.Value.CertificateRequestState != CertificateRequestState.Accepted) {
                    throw new ResourceInvalidStateException("The record is not in a valid state for this operation.");
                }
                request.Value.CertificateRequestState = newStateRemoved ?
                    CertificateRequestState.Removed : CertificateRequestState.Deleted;


                // no need to delete pk for new & rejected requests
                if (!newStateRemoved && first &&
                    request.Value.PrivateKeyFormat != null) {
                    try {
                        await _vaultClient.DeletePrivateKeyAsync(request.Value.CertificateGroupId, requestId);
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
                request.Value.SigningRequest = null;
                request.Value.PrivateKeyFormat = null;
                request.Value.PrivateKeyPassword = null;
                request.Value.DeleteTime = DateTime.UtcNow;
                try {
                    await _certificateRequests.ReplaceAsync(request, request.Value);
                }
                catch (ResourceOutOfDateException) {
                    continue;
                }
                break;
            }
        }

        /// <inheritdoc/>
        public async Task RevokeRequestCertificateAsync(string requestId) {
            if (string.IsNullOrEmpty(requestId)) {
                throw new ArgumentNullException(nameof(requestId),
                    "The request id must be provided");
            }
            while (true) {
                var request = await _certificateRequests.GetAsync<CertificateRequestDocument>(
                    requestId);
                if (request == null) {
                    throw new ResourceNotFoundException("Request not found");
                }

                if (request.Value.Certificate == null ||
                    request.Value.CertificateRequestState != CertificateRequestState.Deleted) {
                    throw new ResourceInvalidStateException(
                        "The record is not in a valid state for this operation.");
                }

                request.Value.CertificateRequestState = CertificateRequestState.Revoked;
                // erase information which is not required anymore
                request.Value.PrivateKeyFormat = null;
                request.Value.SigningRequest = null;
                request.Value.PrivateKeyPassword = null;

                try {
                    var cert = new X509Certificate2(request.Value.Certificate).ToServiceModel();
                    var crl = await _vaultClient.RevokeSingleCertificateAsync(
                        request.Value.CertificateGroupId, cert);
                }
                catch (Exception e) {
                    var error = new StringBuilder();
                    error.Append("Error Revoking Certificate=" + e.Message);
                    error.Append("\r\nGroupId=" + request.Value.CertificateGroupId);
                    throw new ResourceInvalidStateException(error.ToString());
                }

                request.Value.RevokeTime = DateTime.UtcNow;
                try {
                    await _certificateRequests.ReplaceAsync(request, request.Value);
                }
                catch (ResourceOutOfDateException) {
                    continue;
                }
                break;
            }
        }

        /// <inheritdoc/>
        public async Task PurgeRequestAsync(string requestId) {
            if (string.IsNullOrEmpty(requestId)) {
                throw new ArgumentNullException(nameof(requestId),
                    "The request id must be provided");
            }
            while (true) {
                var request = await _certificateRequests.GetAsync<CertificateRequestDocument>(
                    requestId);
                if (request == null) {
                    return;
                }
                if (request.Value.CertificateRequestState != CertificateRequestState.Revoked &&
                    request.Value.CertificateRequestState != CertificateRequestState.Rejected &&
                    request.Value.CertificateRequestState != CertificateRequestState.New &&
                    request.Value.CertificateRequestState != CertificateRequestState.Removed) {
                    throw new ResourceInvalidStateException(
                        "The record is not in a valid state for this operation.");
                }

                try {
                    await _certificateRequests.DeleteAsync(request);
                }
                catch (ResourceOutOfDateException) {
                    continue;
                }
                break;
            }
        }

        /// <inheritdoc/>
        public async Task RevokeAllRequestsAsync(string groupId, bool? allVersions) {


            var queryParameters = new Dictionary<string, object>();
            var query = "SELECT * FROM CertificateRequest r WHERE r.CertificateRequestState = @state";
            queryParameters.Add("@state", CertificateRequestState.Deleted.ToString());

            var results = _certificateRequests.OpenSqlClient().Query<CertificateRequestDocument>(
                query, queryParameters);
            var deletedRequests = await results.AllAsync();
            if (deletedRequests == null || !deletedRequests.Any()) {
                return;
            }
            var revokedId = new List<string>();
            var certCollection = new X509Certificate2Collection();
            foreach (var request in deletedRequests.Select(r => r.Value)) {
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

            foreach (var requestId in deletedRequests.Select(r => r.Value.RequestId)) {
                while(true) {
                    var request = await _certificateRequests.GetAsync<CertificateRequestDocument>(
                        requestId);
                    if (request == null ||
                        request.Value.CertificateRequestState != CertificateRequestState.Deleted) {
                        // skip, there may have been a concurrent update to the database.
                        continue;
                    }

                    // TODO: test for remaining certificates

                    request.Value.CertificateRequestState = CertificateRequestState.Revoked;
                    request.Value.RevokeTime = DateTime.UtcNow;
                    // erase information which is not required anymore
                    request.Value.Certificate = null;
                    request.Value.PrivateKeyFormat = null;
                    request.Value.SigningRequest = null;
                    request.Value.PrivateKeyPassword = null;

                    try {
                        await _certificateRequests.ReplaceAsync(request, request.Value);
                    }
                    catch (ResourceOutOfDateException) {
                        continue;
                    }
                    break;
                }
            }
        }

        /// <inheritdoc/>
        public async Task<FetchCertificateRequestResultModel> FetchResultAsync(string requestId,
            string applicationId) {
            if (string.IsNullOrEmpty(requestId)) {
                throw new ArgumentNullException(nameof(requestId), "The request id must be provided");
            }
            var registration = await _applicationsDatabase.GetApplicationAsync(applicationId);
            var request = await _certificateRequests.GetAsync<CertificateRequestDocument>(
                requestId);
            if (request == null) {
                throw new ResourceNotFoundException("Request not found");
            }
            if (request.Value.ApplicationId != registration.Application.ApplicationId) {
                throw new ArgumentException("The recordId does not match the applicationId.");
            }

            switch (request.Value.CertificateRequestState) {
                case CertificateRequestState.New:
                case CertificateRequestState.Rejected:
                case CertificateRequestState.Revoked:
                case CertificateRequestState.Deleted:
                case CertificateRequestState.Removed:
                    return new FetchCertificateRequestResultModel {
                        Request = new CertificateRequestRecordModel {
                            State = request.Value.CertificateRequestState,
                            ApplicationId = applicationId,
                            RequestId = requestId
                        }
                    };
                case CertificateRequestState.Accepted:
                case CertificateRequestState.Approved:
                    break;
                default:
                    throw new ResourceInvalidStateException(
                        "The record is not in a valid state for this operation.");
            }

            // get private key
            byte[] privateKey = null;
            if (request.Value.CertificateRequestState == CertificateRequestState.Approved &&
                request.Value.PrivateKeyFormat != null) {
                try {
                    privateKey = await _vaultClient.GetPrivateKeyAsync(
                        request.Value.CertificateGroupId, requestId, request.Value.PrivateKeyFormat);
                }
                catch {
                    // intentionally ignore error when reading private key
                    // it may have been disabled by keyvault due to inactivity...
                    request.Value.PrivateKeyFormat = null;
                    privateKey = null;
                }
            }
            return new FetchCertificateRequestResultModel {
                Request = request.Value.ToServiceModel(),
                SignedCertificate = request.Value.Certificate,
                PrivateKey = privateKey,
                AuthorityId = request.Value.AuthorityId
            };
        }

        /// <inheritdoc/>
        public async Task<CertificateRequestRecordModel> GetRequestAsync(string requestId) {
            if (string.IsNullOrEmpty(requestId)) {
                throw new ArgumentNullException(nameof(requestId),
                    "The request id must be provided");
            }
            var request = await _certificateRequests.GetAsync<CertificateRequestDocument>(
                requestId);
            if (request == null) {
                throw new ResourceNotFoundException("Request not found");
            }
            switch (request.Value.CertificateRequestState) {
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
            return request.Value.ToServiceModel();
        }

        /// <inheritdoc/>
        public async Task<CertificateRequestQueryResultModel> QueryRequestsAsync(string appId,
            CertificateRequestState? state, string nextPageLink, int? maxResults) {
            var client = _certificateRequests.OpenSqlClient();
            var results = nextPageLink != null ?
                client.Continue<CertificateRequestDocument>(nextPageLink, maxResults) :
                client.Query<CertificateRequestDocument>(
                    CreateQuery(appId, state, out var queryParameters), 
                    queryParameters, maxResults);
            if (!results.HasMore()) {
                return new CertificateRequestQueryResultModel();
            }
            var requests = await results.ReadAsync();
            return new CertificateRequestQueryResultModel {
                NextPageLink = results.ContinuationToken,
                Requests = requests.Select(r => r.Value.ToServiceModel()).ToList()
            };
        }

        /// <summary>
        /// Create query string from parameters
        /// </summary>
        /// <param name="appId"></param>
        /// <param name="state"></param>
        /// <param name="queryParameters"></param>
        /// <returns></returns>
        private static string CreateQuery(string appId, CertificateRequestState? state, 
            out Dictionary<string, object> queryParameters) {
            queryParameters = new Dictionary<string, object>();
            var query = "SELECT * FROM CertificateRequest r WHERE ";
            if (appId == null && state == null) {
                query += " r.CertificateRequestState != @state";
                queryParameters.Add("@state", CertificateRequestState.Deleted.ToString());
            }
            else if (appId != null && state != null) {
                query += " r.ApplicationId = @appId AND r.CertificateRequestState = @state ";
                queryParameters.Add("@appId", appId);
                queryParameters.Add("@state", state.ToString());
            }
            else if (appId != null) {
                query += " r.ApplicationId = @appId";
                queryParameters.Add("@appId", appId);
            }
            else {
                query += " r.CertificateRequestState = @state ";
                queryParameters.Add("@state", state.ToString());
            }
            return query;
        }

        /// <summary>
        /// Returns the next free, largest, application ID value.
        /// This is the ID value used for sorting in GDS queries.
        /// </summary>
        /// <returns></returns>
        private async Task<uint> GetNextRecordIdAsync() {
            try {
                var query = _certificateRequests.OpenSqlClient().Query<CertificateRequestDocument>(
                    "SELECT TOP 1 * FROM CertificateRequests a WHERE " +
                        $"a.{nameof(CertificateRequestDocument.ClassType)} = {CertificateRequestDocument.ClassTypeName} ORDER BY " +
                        $"a.{nameof(CertificateRequestDocument.ID)} DESC");

                var maxIDEnum = await query.AllAsync();
                var maxID = maxIDEnum.SingleOrDefault();
                return (maxID != null) ? maxID.Value.ID + 1 : 1;
            }
            catch {
                return 1;
            }
        }

        private readonly IApplicationRegistry _applicationsDatabase;
        private readonly ICertificateStorage _vaultClient;
        private readonly ILogger _logger;
        private readonly IDocuments _certificateRequests;
    }
}
