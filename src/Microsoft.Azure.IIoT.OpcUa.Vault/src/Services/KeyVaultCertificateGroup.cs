// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------


namespace Microsoft.Azure.IIoT.OpcUa.Vault.Services {
    using Microsoft.AspNetCore.Http;
    using Microsoft.Azure.IIoT.Auth.Clients;
    using Microsoft.Azure.IIoT.OpcUa.Vault.KeyVault;
    using Microsoft.Azure.IIoT.OpcUa.Vault.KeyVault.Models;
    using Microsoft.Azure.IIoT.OpcUa.Vault.Models;
    using Newtonsoft.Json;
    using Opc.Ua;
    using Serilog;
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Security.Cryptography.X509Certificates;
    using System.Threading.Tasks;

    /// <summary>
    /// The Key Vault implementation of the Certificate Group.
    /// </summary>
    public sealed class KeyVaultCertificateGroup : ICertificateGroup {

        /// <inheritdoc/>
        public KeyVaultCertificateGroup(IVaultConfig config, IClientConfig auth,
            ILogger logger) {
            _config = config;
            _auth = auth;
            _serviceHost = _config.ServiceHost;
            _keyVaultServiceClient = new KeyVaultServiceClient(_groupSecret,
                config.KeyVaultBaseUrl, true, logger);
            if (auth != null &&
                !string.IsNullOrEmpty(auth.AppId) && !string.IsNullOrEmpty(auth.AppSecret)) {
                _keyVaultServiceClient.SetAuthenticationClientCredential(auth.AppId, auth.AppSecret);
            }
            else {
                // uses MSI or dev account
                _keyVaultServiceClient.SetAuthenticationTokenProvider();
            }
            _logger = logger;
            _logger.Debug("Creating new instance of `KeyVault` service " + config.KeyVaultBaseUrl);
        }

        /// <inheritdoc/>
        public KeyVaultCertificateGroup(KeyVaultServiceClient keyVaultServiceClient,
            IVaultConfig config, IClientConfig auth, ILogger logger) {
            _config = config;
            _auth = auth;
            _serviceHost = _config.ServiceHost;
            _keyVaultServiceClient = keyVaultServiceClient;
            _logger = logger;
            _logger.Debug("Creating new on behalf of instance of `KeyVault` service ");
        }

        /// <inheritdoc/>
        public async Task InitializeAsync() {
            var certificateGroupCollection =
                await GetCertificateGroupConfigurationCollectionAsync().ConfigureAwait(false);
            foreach (var certificateGroupConfiguration in certificateGroupCollection.Groups) {
                KeyVaultCertificateGroupProvider certificateGroup = null;
                try {
                    certificateGroup = KeyVaultCertificateGroupProvider.Create(_keyVaultServiceClient,
                        certificateGroupConfiguration, _config.ServiceHost);
                    await certificateGroup.Init().ConfigureAwait(false);
#if LOADPRIVATEKEY
                    // test if private key can be loaded
                    await certificateGroup.LoadSigningKeyAsync(null, null);
#endif
                    continue;
                }
                catch (Exception ex) {
                    _logger.Error("Failed to initialize certificate group. ", ex);
                    if (certificateGroup == null) {
                        throw ex;
                    }
                }
                _logger.Information("Create new issuer CA certificate for group. ", certificateGroup);
                if (!await certificateGroup.CreateIssuerCACertificateAsync().ConfigureAwait(false)) {
                    _logger.Error("Failed to create issuer CA certificate. ", certificateGroup);
                }
            }
        }

        /// <inheritdoc/>
        public Task<ICertificateGroup> SendOnBehalfOfRequestAsync(HttpRequest request) {
            try {
                var accessToken = request.Headers["Authorization"];
                var token = accessToken.First().Remove(0, "Bearer ".Length);
                var authority = string.IsNullOrEmpty(_auth.InstanceUrl) ?
                    kAuthority : _auth.InstanceUrl;
                if (!authority.EndsWith("/", StringComparison.Ordinal)) {
                    authority += "/";
                }
                authority += _auth.TenantId;
                var serviceClientCredentials =
                    new KeyVaultCredentials(token, authority,
                        _config.KeyVaultResourceId, _auth.AppId,
                        _auth.AppSecret);
                var keyVaultServiceClient = new KeyVaultServiceClient(
                    _groupSecret, _config.KeyVaultBaseUrl, true, _logger);
                keyVaultServiceClient.SetServiceClientCredentials(serviceClientCredentials);
                return Task.FromResult<ICertificateGroup>(new KeyVaultCertificateGroup(
                    keyVaultServiceClient,
                    _config,
                    _auth,
                    _logger
                    ));
            }
            catch (Exception ex) {
                // try default
                _logger.Error(ex, "Failed to create on behalf Key Vault client. ");
            }
            return Task.FromResult<ICertificateGroup>(this);
        }

        /// <inheritdoc/>
        public Task<string[]> GetCertificateGroupIdsAsync() =>
            KeyVaultCertificateGroupProvider.GetCertificateGroupIds(_keyVaultServiceClient);

        /// <inheritdoc/>
        public Task<CertificateGroupConfigurationModel> GetCertificateGroupConfigurationAsync(
            string id) => KeyVaultCertificateGroupProvider.GetCertificateGroupConfiguration(
                _keyVaultServiceClient, id);

        /// <inheritdoc/>
        public Task<CertificateGroupConfigurationModel> UpdateCertificateGroupConfigurationAsync(
            string id, CertificateGroupConfigurationModel config) =>
            KeyVaultCertificateGroupProvider.UpdateCertificateGroupConfiguration(
                _keyVaultServiceClient, id, config);

        /// <inheritdoc/>
        public Task<CertificateGroupConfigurationModel> CreateCertificateGroupConfigurationAsync(
            string id, string subject, string certType) =>
            KeyVaultCertificateGroupProvider.CreateCertificateGroupConfiguration(
                _keyVaultServiceClient, id, subject, certType);

        /// <inheritdoc/>
        public async Task<CertificateGroupConfigurationCollectionModel> GetCertificateGroupConfigurationCollectionAsync() {
            var json = await _keyVaultServiceClient.GetCertificateConfigurationGroupsAsync()
                .ConfigureAwait(false);
            var groups = JsonConvert.DeserializeObject<IList<CertificateGroupConfigurationModel>>(json);
            return new CertificateGroupConfigurationCollectionModel { Groups = groups };
        }

        /// <inheritdoc/>
        public async Task<X509CrlModel> RevokeCertificateAsync(string id, X509CertificateModel certificate) {
            var certificateGroup = await KeyVaultCertificateGroupProvider.Create(
                _keyVaultServiceClient, id, _serviceHost).ConfigureAwait(false);
            await certificateGroup.RevokeCertificateAsync(certificate.ToStackModel())
                .ConfigureAwait(false);
            return certificateGroup.Crl.ToServiceModel();
        }

        /// <inheritdoc/>
        public async Task<X509CertificateCollectionModel> RevokeCertificatesAsync(string id,
            X509CertificateCollectionModel certificates) {
            var certificateGroup = await KeyVaultCertificateGroupProvider.Create(
                _keyVaultServiceClient, id, _serviceHost).ConfigureAwait(false);
            var result = await certificateGroup.RevokeCertificatesAsync(certificates.ToStackModel())
                .ConfigureAwait(false);
            return result.ToServiceModel(null);
        }

        /// <inheritdoc/>
        public async Task<X509CertificateModel> CreateIssuerCACertificateAsync(string id) {
            var certificateGroup = await KeyVaultCertificateGroupProvider.Create(
                _keyVaultServiceClient, id, _serviceHost).ConfigureAwait(false);
            if (await certificateGroup.CreateIssuerCACertificateAsync().ConfigureAwait(false)) {
                return certificateGroup.Certificate.ToServiceModel();
            }
            return null;
        }

        /// <inheritdoc/>
        public async Task<X509CertificateModel> SigningRequestAsync(string id,
            string applicationUri, byte[] certificateRequest) {
            var certificateGroup = await KeyVaultCertificateGroupProvider.Create(
                _keyVaultServiceClient, id, _serviceHost).ConfigureAwait(false);
            var app = new Opc.Ua.Gds.ApplicationRecordDataType {
                ApplicationNames = new LocalizedTextCollection(),
                ApplicationUri = applicationUri
            };
            var cert = await certificateGroup.SigningRequestAsync(
                app, null, certificateRequest).ConfigureAwait(false);
            return cert.ToServiceModel();
        }

        /// <inheritdoc/>
        public async Task<X509CertificatePrivateKeyPairModel> NewKeyPairRequestAsync(
            string id, string requestId, string applicationUri, string subjectName,
            string[] domainNames, string privateKeyFormat, string privateKeyPassword) {
            var certificateGroup = await KeyVaultCertificateGroupProvider.Create(
                _keyVaultServiceClient, id, _serviceHost).ConfigureAwait(false);
            var app = new Opc.Ua.Gds.ApplicationRecordDataType {
                ApplicationNames = new LocalizedTextCollection(),
                ApplicationUri = applicationUri
            };
            var keyPair = await certificateGroup.NewKeyPairRequestAsync(
                app, subjectName, domainNames, privateKeyFormat, privateKeyPassword)
                    .ConfigureAwait(false);
            await certificateGroup.ImportCertKeySecret(id, requestId, keyPair.PrivateKey,
                keyPair.PrivateKeyFormat);
            return keyPair.ToServiceModel();
        }

        /// <inheritdoc/>
        public async Task<X509CertificateCollectionModel> GetIssuerCACertificateVersionsAsync(
            string id, bool? withCertificates, string nextPageLink, int? pageSize) {
            // TODO: implement withCertificates
            var certificateGroup = await KeyVaultCertificateGroupProvider.Create(
                _keyVaultServiceClient, id, _serviceHost).ConfigureAwait(false);
            var (result, nextLink) = await _keyVaultServiceClient.GetCertificateVersionsAsync(
                id, null, nextPageLink, pageSize);
            return result.ToServiceModel(nextLink);
        }

        /// <inheritdoc/>
        public async Task<X509CertificateCollectionModel> GetIssuerCACertificateChainAsync(
            string id, string thumbPrint = null, string nextPageLink = null, int? pageSize = null) {
            // TODO: implement paging (low priority, only when long chains are expected)
            var certificateGroup = await KeyVaultCertificateGroupProvider.Create(
                _keyVaultServiceClient, id, _serviceHost).ConfigureAwait(false);
            var cert = await certificateGroup.GetIssuerCACertificateAsync(
                id, thumbPrint).ConfigureAwait(false);
            return new X509Certificate2Collection(cert).ToServiceModel(null);
        }

        /// <inheritdoc/>
        public async Task<X509CrlCollectionModel> GetIssuerCACrlChainAsync(string id,
            string thumbPrint = null, string nextPageLink = null, int? pageSize = null) {
            // TODO: implement paging (low priority, only when long chains are expected)
            var certificateGroup = await KeyVaultCertificateGroupProvider.Create(
                _keyVaultServiceClient, id, _serviceHost).ConfigureAwait(false);
            var crl = await certificateGroup.GetIssuerCACrlAsync(
                id, thumbPrint).ConfigureAwait(false);
            return new X509CrlCollectionModel {
                Chain = new List<X509CrlModel> { crl.ToServiceModel() }
            };
        }

        /// <inheritdoc/>
        public async Task<byte[]> LoadPrivateKeyAsync(string id, string requestId,
            string privateKeyFormat) {
            var certificateGroup = await KeyVaultCertificateGroupProvider.Create(
                _keyVaultServiceClient, id, _serviceHost).ConfigureAwait(false);
            return await certificateGroup.LoadCertKeySecret(id, requestId, privateKeyFormat);
        }

        /// <inheritdoc/>
        public async Task AcceptPrivateKeyAsync(string id, string requestId) {
            var certificateGroup = await KeyVaultCertificateGroupProvider.Create(
                _keyVaultServiceClient, id, _serviceHost).ConfigureAwait(false);
            await certificateGroup.AcceptCertKeySecret(id, requestId);
        }

        /// <inheritdoc/>
        public async Task DeletePrivateKeyAsync(string id, string requestId) {
            var certificateGroup = await KeyVaultCertificateGroupProvider.Create(
                _keyVaultServiceClient, id, _serviceHost).ConfigureAwait(false);
            await certificateGroup.DeleteCertKeySecret(id, requestId);
        }

        /// <inheritdoc/>
        public async Task<TrustListModel> GetTrustListAsync(string id,
            string nextPageLink = null, int? pageSize = null) {
            var trustlist = await _keyVaultServiceClient.GetTrustListAsync(
                id, pageSize, nextPageLink);
            return trustlist.ToServiceModel();
        }

        /// <inheritdoc/>
        public Task PurgeAsync(string configId = null, string groupId = null) =>
            _keyVaultServiceClient.PurgeAsync(configId, groupId);

        private readonly IVaultConfig _config;
        private readonly IClientConfig _auth;
        private readonly KeyVaultServiceClient _keyVaultServiceClient;
        private readonly ILogger _logger;
        private readonly string _serviceHost;
        private readonly string _groupSecret = "groups";
        private const string kAuthority = "https://login.microsoftonline.com/";
    }
}
