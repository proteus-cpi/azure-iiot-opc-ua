// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace Microsoft.Azure.IIoT.OpcUa.Vault.Services {
    using Microsoft.Azure.IIoT.Exceptions;
    using Microsoft.Azure.IIoT.OpcUa.Registry;
    using Microsoft.Azure.IIoT.OpcUa.Registry.Models;
    using Microsoft.Azure.IIoT.OpcUa.Vault;
    using Microsoft.Azure.IIoT.OpcUa.Vault.Models;
    using Microsoft.Azure.IIoT.OpcUa.Vault.Services.Models;
    using Microsoft.Azure.IIoT.Storage;
    using Microsoft.Azure.IIoT.Storage.Default;
    using Microsoft.Azure.IIoT.Utils;
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
    /// Cosmos db certificate request management workflow service
    /// </summary>
    public sealed class CertificateManager : ICertificateManager,
        IRequestManagement, IApplicationChangeListener {

        /// <summary>
        /// Create certificate request
        /// </summary>
        /// <param name="registry"></param>
        /// <param name="groups"></param>
        /// <param name="db"></param>
        /// <param name="logger"></param>
        public CertificateManager(IApplicationRegistry registry,
            ICertificateDirectory groups, IItemContainerFactory db,
            ILogger logger) {

            _registry = registry ?? throw new ArgumentNullException(nameof(registry));
            _groups = groups ?? throw new ArgumentNullException(nameof(groups));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            if (db == null) {
                throw new ArgumentNullException(nameof(db));
            }

            var container = db.OpenAsync().Result;
            _requests = container.AsDocuments();
            _index = new ContainerIndex(container);
        }

        /// <inheritdoc/>
        public async Task<string> StartSigningRequestAsync(
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
            var application = await _registry.GetApplicationAsync(
                request.ApplicationId);

            var recordId = await _index.AllocateAsync();
            while (true) {
                var document = new CertificateRequestDocument {
                    RequestId = Guid.NewGuid().ToString(),
                    AuthorityId = authorityId,
                    ID = recordId,
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
                    var result = await _requests.AddAsync(document);
                    return result.Value.RequestId;
                }
                catch (ConflictingResourceException) {
                    continue;
                }
                catch {
                    await Try.Async(() => _index.FreeAsync(recordId));
                    throw;
                }
            }
        }

        /// <inheritdoc/>
        public async Task<string> StartNewKeyPairRequestAsync(
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

            var registration = await _registry.GetApplicationAsync(
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

            var recordId = await _index.AllocateAsync();
            while (true) {
                var document = new CertificateRequestDocument {
                    RequestId = Guid.NewGuid().ToString(),
                    AuthorityId = authorityId,
                    ID = recordId,
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
                    var result = await _requests.AddAsync(document);
                    return result.Value.RequestId;
                }
                catch (ConflictingResourceException) {
                    continue;
                }
                catch {
                    await Try.Async(() => _index.FreeAsync(recordId));
                    throw;
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
                var document = await _requests.GetAsync<CertificateRequestDocument>(
                    requestId);
                if (document == null) {
                    throw new ResourceNotFoundException("Request not found");
                }
                var request = document.Value.Clone();
                if (request.CertificateRequestState != CertificateRequestState.New) {
                    throw new ResourceInvalidStateException(
                        "The record is not in a valid state for this operation.");
                }

                var registration = await _registry.GetApplicationAsync(
                    request.ApplicationId);

                request.CertificateRequestState = CertificateRequestState.Approved;
                X509CertificateModel certificate;
                if (request.SigningRequest != null) {
                    try {
                        certificate = await _groups.StartSigningRequestAsync(
                            request.CertificateGroupId, registration.Application.ApplicationUri,
                            request.SigningRequest);
                        request.Certificate = certificate.ToRawData();
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
                        newKeyPair = await _groups.StartNewKeyPairRequestAsync(
                            request.CertificateGroupId,
                            requestId,
                            registration.Application.ApplicationUri,
                            request.SubjectName,
                            request.DomainNames,
                            Enum.Parse<PrivateKeyFormat>(request.PrivateKeyFormat),
                            request.PrivateKeyPassword);
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
                    request.Certificate = newKeyPair.Certificate.ToRawData();
                    // ignore private key, it is stored in KeyVault
                }

                request.ApproveRejectTime = DateTime.UtcNow;
                try {
                    await _requests.ReplaceAsync(document, request);
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
                throw new ArgumentNullException(nameof(requestId),
                    "The request id must be provided");
            }
            while (true) {
                var document = await _requests.GetAsync<CertificateRequestDocument>(
                    requestId);
                if (document == null) {
                    throw new ResourceNotFoundException("Request not found");
                }
                var request = document.Value.Clone();
                if (request.CertificateRequestState != CertificateRequestState.New) {
                    throw new ResourceInvalidStateException(
                        "The record is not in a valid state for this operation.");
                }

                var application = await _registry.GetApplicationAsync(
                    request.ApplicationId);

                request.CertificateRequestState = CertificateRequestState.Rejected;
                // erase information which is not required anymore
                request.PrivateKeyFormat = null;
                request.SigningRequest = null;
                request.PrivateKeyPassword = null;
                request.ApproveRejectTime = DateTime.UtcNow;

                try {
                    await _requests.ReplaceAsync(document, request);
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
                var document = await _requests.GetAsync<CertificateRequestDocument>(
                    requestId);
                if (document == null) {
                    throw new ResourceNotFoundException("Request not found");
                }
                var request = document.Value.Clone();
                if (request.CertificateRequestState != CertificateRequestState.Approved) {
                    throw new ResourceInvalidStateException(
                        "The record is not in a valid state for this operation.");
                }


                if (request.PrivateKeyFormat != null && first) {
                    try {
                        await _groups.DeletePrivateKeyAsync(
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
                    await _requests.ReplaceAsync(document, request);
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
                var document = await _requests.GetAsync<CertificateRequestDocument>(
                    requestId);
                if (document == null) {
                    throw new ResourceNotFoundException("Request not found");
                }
                var request = document.Value.Clone();

                var newStateRemoved =
                    request.CertificateRequestState == CertificateRequestState.New ||
                    request.CertificateRequestState == CertificateRequestState.Rejected;

                if (!newStateRemoved &&
                    request.CertificateRequestState != CertificateRequestState.Approved &&
                    request.CertificateRequestState != CertificateRequestState.Accepted) {
                    throw new ResourceInvalidStateException(
                        "The record is not in a valid state for this operation.");
                }
                request.CertificateRequestState = newStateRemoved ?
                    CertificateRequestState.Removed : CertificateRequestState.Deleted;

                // no need to delete pk for new & rejected requests
                if (!newStateRemoved && first &&
                    request.PrivateKeyFormat != null) {
                    try {
                        await _groups.DeletePrivateKeyAsync(request.CertificateGroupId, requestId);
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
                    await _requests.ReplaceAsync(document, request);
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
                var document = await _requests.GetAsync<CertificateRequestDocument>(
                    requestId);
                if (document == null) {
                    throw new ResourceNotFoundException("Request not found");
                }
                var request = document.Value.Clone();
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
                    var crl = await _groups.RevokeSingleCertificateAsync(
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
                    await _requests.ReplaceAsync(document, request);
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
                var request = await _requests.GetAsync<CertificateRequestDocument>(
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
                    await _requests.DeleteAsync(request);
                    await Try.Async(() => _index.FreeAsync(request.Value.ID));
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

            var results = _requests.OpenSqlClient().Query<CertificateRequestDocument>(
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

            var remainingCertificates = await _groups.RevokeCertificatesAsync(
                groupId, certCollection.ToServiceModel(null));

            foreach (var requestId in deletedRequests.Select(r => r.Value.RequestId)) {
                while (true) {
                    var document = await _requests.GetAsync<CertificateRequestDocument>(
                        requestId);
                    if (document == null) {
                        // skip, there may have been a concurrent update to the database.
                        continue;
                    }
                    var request = document.Value.Clone();
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
                        await _requests.ReplaceAsync(document, request);
                    }
                    catch (ResourceOutOfDateException) {
                        continue;
                    }
                    break;
                }
            }
        }

        /// <inheritdoc/>
        public async Task<FinishCertificateRequestResultModel> FinishRequestAsync(string requestId) {
            if (string.IsNullOrEmpty(requestId)) {
                throw new ArgumentNullException(nameof(requestId), "The request id must be provided");
            }
            var document = await _requests.GetAsync<CertificateRequestDocument>(
                requestId);
            if (document == null) {
                throw new ResourceNotFoundException("Request not found");
            }

            switch (document.Value.CertificateRequestState) {
                case CertificateRequestState.New:
                case CertificateRequestState.Rejected:
                case CertificateRequestState.Revoked:
                case CertificateRequestState.Deleted:
                case CertificateRequestState.Removed:
                    return new FinishCertificateRequestResultModel {
                        Request = new CertificateRequestRecordModel {
                            State = document.Value.CertificateRequestState,
                            ApplicationId = document.Value.ApplicationId,
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
            if (document.Value.CertificateRequestState == CertificateRequestState.Approved &&
                document.Value.PrivateKeyFormat != null) {
                try {
                    privateKey = await _groups.GetPrivateKeyAsync(
                        document.Value.CertificateGroupId, requestId,
                            Enum.Parse<PrivateKeyFormat>(document.Value.PrivateKeyFormat));
                }
                catch {
                    // intentionally ignore error when reading private key
                    // it may have been disabled by keyvault due to inactivity...
                    document.Value.PrivateKeyFormat = null;
                    privateKey = null;
                }
            }
            return new FinishCertificateRequestResultModel {
                Request = document.Value.ToServiceModel(),
                SignedCertificate = document.Value.Certificate,
                PrivateKey = privateKey,
                AuthorityId = document.Value.AuthorityId
            };
        }

        /// <inheritdoc/>
        public async Task<CertificateRequestRecordModel> GetRequestAsync(string requestId) {
            if (string.IsNullOrEmpty(requestId)) {
                throw new ArgumentNullException(nameof(requestId),
                    "The request id must be provided");
            }
            var document = await _requests.GetAsync<CertificateRequestDocument>(
                requestId);
            if (document == null) {
                throw new ResourceNotFoundException("Request not found");
            }
            switch (document.Value.CertificateRequestState) {
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
            return document.Value.ToServiceModel();
        }

        /// <inheritdoc/>
        public async Task<CertificateRequestQueryResultModel> QueryRequestsAsync(
            CertificateRequestQueryRequestModel query, string nextPageLink, int? maxResults) {
            var client = _requests.OpenSqlClient();
            var results = nextPageLink != null ?
                client.Continue<CertificateRequestDocument>(nextPageLink, maxResults) :
                client.Query<CertificateRequestDocument>(
                    CreateQuery(query?.ApplicationId, query?.State, out var queryParameters),
                    queryParameters, maxResults);
            if (!results.HasMore()) {
                return new CertificateRequestQueryResultModel();
            }
            var documents = await results.ReadAsync();
            return new CertificateRequestQueryResultModel {
                NextPageLink = results.ContinuationToken,
                Requests = documents.Select(r => r.Value.ToServiceModel()).ToList()
            };
        }

        /// <inheritdoc/>
        public Task OnEventAsync(ApplicationEvent eventType, ApplicationInfoModel application) {
            if (eventType == ApplicationEvent.Unregistered) {
                // When the application is deleted, we shall delete all its requests
                return DeleteAllApplicationRequests(application.ApplicationId);
            }
            return Task.CompletedTask;
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
        /// Delete all requests for the given application
        /// </summary>
        /// <param name="applicationId"></param>
        /// <returns></returns>
        private async Task DeleteAllApplicationRequests(string applicationId) {
            string nextPageLink = null;
            do {
                var result = await QueryRequestsAsync(new CertificateRequestQueryRequestModel {
                    ApplicationId = applicationId
                }, nextPageLink, null);
                foreach (var request in result.Requests) {
                    if (request.State < CertificateRequestState.Deleted) {
                        await Try.Async(() => DeleteRequestAsync(request.RequestId));
                    }
                }
                nextPageLink = result.NextPageLink;
            } while (nextPageLink != null);
        }

        private readonly IApplicationRegistry _registry;
        private readonly ICertificateDirectory _groups;
        private readonly ILogger _logger;
        private readonly IDocuments _requests;
        private readonly IContainerIndex _index;
    }
}
