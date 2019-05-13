// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------


namespace Microsoft.Azure.IIoT.OpcUa.Vault.Services {
    using Microsoft.Azure.IIoT.OpcUa.Vault.KeyVault;
    using Microsoft.Azure.IIoT.OpcUa.Vault.Models;
    using Microsoft.Azure.IIoT.OpcUa.Vault.KeyVault.Clients;
    using Microsoft.Azure.IIoT.Exceptions;
    using Opc.Ua;
    using Serilog;
    using System.Collections.Generic;
    using System.Security.Cryptography.X509Certificates;
    using System.Threading.Tasks;
    using System;
    using Autofac;


    /// <summary>
    /// Key Vault Certificate Group services
    /// </summary>
    public sealed class KeyVaultGroupServices : IGroupServices, IStartable {

        /// <summary>
        /// Create vault client
        /// </summary>
        /// <param name="registry"></param>
        /// <param name="client"></param>
        /// <param name="config"></param>
        /// <param name="logger"></param>
        public KeyVaultGroupServices(IGroupRegistry registry,
            IKeyVaultServiceClient client, IVaultConfig config, ILogger logger) {
            _config = config ?? throw new ArgumentNullException(nameof(config));
            _registry = registry ?? throw new ArgumentNullException(nameof(registry));
            _client = client ?? throw new ArgumentNullException(nameof(client));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        /// <inheritdoc/>
        public void Start() {
            InitializeAsync().Wait();
        }

        /// <inheritdoc/>
        public async Task<X509CrlModel> RevokeSingleCertificateAsync(string groupId,
            X509CertificateModel certificate) {
            var group = await GetGroupAsync(groupId);
            await group.RevokeCertificateAsync(certificate.ToStackModel());
            return group.Crl.ToServiceModel();
        }

        /// <inheritdoc/>
        public async Task<X509CertificateCollectionModel> RevokeCertificatesAsync(string groupId,
            X509CertificateCollectionModel certificates) {
            var group = await GetGroupAsync(groupId);
            var result = await group.RevokeCertificatesAsync(certificates.ToStackModel());
            return result.ToServiceModel(null);
        }

        /// <inheritdoc/>
        public async Task<X509CertificateModel> CreateIssuerCACertificateAsync(string groupId) {
            var group = await GetGroupAsync(groupId);
            var success = await group.CreateIssuerCACertificateAsync();
            if (success) {
                return group.Certificate.ToServiceModel();
            }
            return null;
        }

        /// <inheritdoc/>
        public async Task<X509CertificateModel> ProcessSigningRequestAsync(string groupId,
            string applicationUri, byte[] certificateRequest) {
            var group = await GetGroupAsync(groupId);
            var app = new Opc.Ua.Gds.ApplicationRecordDataType {
                ApplicationNames = new LocalizedTextCollection(),
                ApplicationUri = applicationUri
            };
            var cert = await group.SigningRequestAsync(app, null, certificateRequest);
            return cert.ToServiceModel();
        }

        /// <inheritdoc/>
        public async Task<X509CertificatePrivateKeyPairModel> ProcessNewKeyPairRequestAsync(
            string groupId, string requestId, string applicationUri, string subjectName,
            string[] domainNames, string privateKeyFormat, string privateKeyPassword) {
            var group = await GetGroupAsync(groupId);
            var app = new Opc.Ua.Gds.ApplicationRecordDataType {
                ApplicationNames = new LocalizedTextCollection(),
                ApplicationUri = applicationUri
            };
            var keyPair = await group.NewKeyPairRequestAsync(
                app, subjectName, domainNames, privateKeyFormat, privateKeyPassword);
            await group.ImportPrivateKeyAsync(requestId, keyPair.PrivateKey,
                keyPair.PrivateKeyFormat);
            return keyPair.ToServiceModel();
        }

        /// <inheritdoc/>
        public async Task<X509CertificateCollectionModel> ListIssuerCACertificateVersionsAsync(
            string groupId, bool? withCertificates, string nextPageLink, int? pageSize) {
            // TODO: implement withCertificates
            var group = await GetGroupAsync(groupId);
            var (result, nextLink) = await _client.ListCertificateVersionsAsync(
                groupId, null, nextPageLink, pageSize);
            return result.ToServiceModel(nextLink);
        }

        /// <inheritdoc/>
        public async Task<X509CertificateCollectionModel> GetIssuerCACertificateChainAsync(
            string groupId, string thumbPrint = null, string nextPageLink = null,
            int? pageSize = null) {
            // TODO: implement paging (low priority, only when long chains are expected)
            var group = await GetGroupAsync(groupId);
            var cert = await group.GetIssuerCACertificateAsync(thumbPrint);
            return new X509Certificate2Collection(cert).ToServiceModel(null);
        }

        /// <inheritdoc/>
        public async Task<X509CrlCollectionModel> GetIssuerCACrlChainAsync(string groupId,
            string thumbPrint = null, string nextPageLink = null, int? pageSize = null) {
            // TODO: implement paging (low priority, only when long chains are expected)
            var group = await GetGroupAsync(groupId);
            var crl = await group.GetIssuerCACrlAsync(thumbPrint);
            return new X509CrlCollectionModel {
                Chain = new List<X509CrlModel> { crl.ToServiceModel() }
            };
        }

        /// <inheritdoc/>
        public async Task<byte[]> GetPrivateKeyAsync(string groupId, string requestId,
            string privateKeyFormat) {
            var group = await GetGroupAsync(groupId);
            return await group.LoadPrivateKeyAsync(requestId, privateKeyFormat);
        }

        /// <inheritdoc/>
        public async Task AcceptPrivateKeyAsync(string groupId, string requestId) {
            var group = await GetGroupAsync(groupId);
            await group.AcceptPrivateKeyAsync(requestId);
        }

        /// <inheritdoc/>
        public async Task DeletePrivateKeyAsync(string groupId, string requestId) {
            var group = await GetGroupAsync(groupId);
            await group.DeletePrivateKeyAsync(requestId);
        }

        /// <inheritdoc/>
        public async Task<TrustListModel> GetTrustListAsync(string groupId,
            string nextPageLink = null, int? pageSize = null) {
            var trustlist = await _client.GetTrustListAsync(groupId, pageSize, nextPageLink);
            return trustlist.ToServiceModel();
        }

        /// <summary>
        /// Open or create group
        /// </summary>
        /// <param name="groupId"></param>
        /// <returns></returns>
        private async Task<KeyVaultCertificateGroup> GetGroupAsync(string groupId) {
            var group = await _registry.GetGroupAsync(groupId);
            if (group == null) {
                throw new ResourceNotFoundException("The certificate group doesn't exist.");
            }
            return new KeyVaultCertificateGroup(_client, group, _config.ServiceHost);
        }

        /// <summary>
        /// Initialize
        /// </summary>
        /// <returns></returns>
        private async Task InitializeAsync() {
            var certificateGroupCollection = await _registry.ListGroupsAsync();
            foreach (var certificateGroupConfiguration in certificateGroupCollection.Groups) {
                KeyVaultCertificateGroup group = null;
                try {
                    group = new KeyVaultCertificateGroup(_client,
                        certificateGroupConfiguration, _config.ServiceHost);
                    await group.Init();
#if LOADPRIVATEKEY
                    // test if private key can be loaded
                    await group.LoadSigningKeyAsync(null, null);
#endif
                    continue;
                }
                catch (Exception ex) {
                    _logger.Error("Failed to initialize certificate group. ", ex);
                    if (group == null) {
                        throw ex;
                    }
                }
                _logger.Information("Create new issuer CA certificate for group. ", group);
                if (!await group.CreateIssuerCACertificateAsync()) {
                    _logger.Error("Failed to create issuer CA certificate. ", group);
                }
            }
        }

        private readonly IVaultConfig _config;
        private readonly IKeyVaultServiceClient _client;
        private readonly ILogger _logger;
        private readonly IGroupRegistry _registry;
    }
}
