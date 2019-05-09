// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------


namespace Microsoft.Azure.IIoT.OpcUa.Vault.Services {
    using Microsoft.Azure.IIoT.OpcUa.Vault.KeyVault;
    using Microsoft.Azure.IIoT.OpcUa.Vault.KeyVault.Models;
    using Microsoft.Azure.IIoT.OpcUa.Vault.Models;
    using Microsoft.Azure.IIoT.Exceptions;
    using Microsoft.Azure.KeyVault.Models;
    using Newtonsoft.Json;
    using Opc.Ua;
    using Serilog;
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    using System.Threading.Tasks;

    /// <summary>
    /// The Key Vault implementation of the Certificate Group.
    /// </summary>
    public sealed class DefaultVaultClient : IVaultClient {

        /// <summary>
        /// Create vault client
        /// </summary>
        /// <param name="keyVaultServiceClient"></param>
        /// <param name="config"></param>
        /// <param name="logger"></param>
        public DefaultVaultClient(IKeyVaultServiceClient keyVaultServiceClient,
            IVaultConfig config, ILogger logger) {
            _config = config;
            _serviceHost = _config.ServiceHost;
            _keyVaultServiceClient = keyVaultServiceClient;
            _logger = logger;
        }

        /// <inheritdoc/>
        public async Task InitializeAsync() {
            var certificateGroupCollection = await ListGroupConfigurationsAsync().ConfigureAwait(false);
            foreach (var certificateGroupConfiguration in certificateGroupCollection.Groups) {
                KeyVaultCertificateGroup certificateGroup = null;
                try {
                    certificateGroup = new KeyVaultCertificateGroup(_keyVaultServiceClient,
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
        public async Task<string[]> GetGroupIdsAsync() {
            // TODO: Read JSON of secret "groups"
            var json = await _keyVaultServiceClient.GetCertificateConfigurationGroupsAsync()
                .ConfigureAwait(false);
            var certificateGroupCollection =
                JsonConvert.DeserializeObject<List<CertificateGroupConfigurationModel>>(json);
            var groups = certificateGroupCollection.Select(cg => cg.Id).ToList();
            return groups.ToArray();
        }

        /// <inheritdoc/>
        public async Task<CertificateGroupConfigurationModel> GetGroupConfigurationAsync(
            string groupId) {
            // TODO: Read JSON of secret "groups"
            var json = await _keyVaultServiceClient.GetCertificateConfigurationGroupsAsync()
                .ConfigureAwait(false);
            var certificateGroupCollection =
                JsonConvert.DeserializeObject<List<CertificateGroupConfigurationModel>>(json);
            return certificateGroupCollection
                .SingleOrDefault(cg => groupId.EqualsIgnoreCase(cg.Id));
        }

        /// <inheritdoc/>
        public async Task<CertificateGroupConfigurationModel> UpdateGroupConfigurationAsync(
            string groupId, CertificateGroupConfigurationModel config) {

            // TODO: configuration should not have id
            if (groupId.ToLower() != config.Id.ToLower()) {
                throw new ArgumentException("groupid doesn't match config groupId");
            }

            // TODO: Read JSON of secret "groups"
            var json = await _keyVaultServiceClient.GetCertificateConfigurationGroupsAsync()
                .ConfigureAwait(false);
            var certificateGroupCollection =
                JsonConvert.DeserializeObject<List<CertificateGroupConfigurationModel>>(json);

            var original = certificateGroupCollection
                .SingleOrDefault(cg => groupId.EqualsIgnoreCase(cg.Id));
            if (original == null) {
                throw new ArgumentException("invalid groupid");
            }

            // TODO: Move to extension
            KeyVaultCertificateGroup.ValidateConfiguration(config);

            var index = certificateGroupCollection.IndexOf(original);
            certificateGroupCollection[index] = config;
            json = JsonConvert.SerializeObject(certificateGroupCollection);
            // update config
            json = await _keyVaultServiceClient.PutCertificateConfigurationGroupsAsync(json)
                .ConfigureAwait(false);
            // read it back to verify
            certificateGroupCollection =
                JsonConvert.DeserializeObject<List<CertificateGroupConfigurationModel>>(json);
            return certificateGroupCollection.SingleOrDefault(
                cg => groupId.EqualsIgnoreCase(cg.Id));
        }

        /// <inheritdoc/>
        public async Task<CertificateGroupConfigurationModel> CreateGroupConfigurationAsync(
            string groupId, string subject, string certType) {
            var config = KeyVaultCertificateGroup.DefaultConfiguration(groupId, subject, certType);
            if (groupId.ToLower() != config.Id.ToLower()) {
                throw new ArgumentException("groupid doesn't match config groupId");
            }

            // TODO: Read JSON of secret "groups" - throw resource not found if not found
            string json;
            IList<CertificateGroupConfigurationModel> certificateGroupCollection =
                new List<CertificateGroupConfigurationModel>();
            try {
                json = await _keyVaultServiceClient.GetCertificateConfigurationGroupsAsync()
                    .ConfigureAwait(false);
                certificateGroupCollection =
                    JsonConvert.DeserializeObject<List<CertificateGroupConfigurationModel>>(json);
            }
            catch (KeyVaultErrorException kex) {
                // TODO: Catch resource not found exception instead
                if (kex.Response.StatusCode != HttpStatusCode.NotFound) {
                    throw kex;
                }
            }

            var original = certificateGroupCollection
                .SingleOrDefault(cg => groupId.EqualsIgnoreCase(cg.Id));
            if (original != null) {
                throw new ArgumentException("groupid already exists");
            }

            // TODO: Extension
            KeyVaultCertificateGroup.ValidateConfiguration(config);

            certificateGroupCollection.Add(config);
            json = JsonConvert.SerializeObject(certificateGroupCollection);

            // TODO: Write JSON of secret "groups" - throw resource not found if not found
            // update config
            json = await _keyVaultServiceClient.PutCertificateConfigurationGroupsAsync(json)
                .ConfigureAwait(false);
            // read it back to verify
            certificateGroupCollection =
                JsonConvert.DeserializeObject<List<CertificateGroupConfigurationModel>>(json);
            return certificateGroupCollection
                .SingleOrDefault(cg => groupId.EqualsIgnoreCase(cg.Id));
        }

        /// <inheritdoc/>
        public async Task<CertificateGroupConfigurationCollectionModel> ListGroupConfigurationsAsync() {
            // TODO: Read JSON of secret "groups" - throw resource not found if not found
            var json = await _keyVaultServiceClient.GetCertificateConfigurationGroupsAsync()
                .ConfigureAwait(false);
            var groups = JsonConvert.DeserializeObject<IList<CertificateGroupConfigurationModel>>(json);
            return new CertificateGroupConfigurationCollectionModel { Groups = groups };
        }


        // Group cert action

        /// <inheritdoc/>
        public async Task<X509CrlModel> RevokeCertificateAsync(string groupId,
            X509CertificateModel certificate) {
            var certificateGroup = await GetGroupAsync(groupId, _serviceHost)
                .ConfigureAwait(false);
            await certificateGroup.RevokeCertificateAsync(certificate.ToStackModel())
                .ConfigureAwait(false);
            return certificateGroup.Crl.ToServiceModel();
        }

        /// <inheritdoc/>
        public async Task<X509CertificateCollectionModel> RevokeCertificatesAsync(string groupId,
            X509CertificateCollectionModel certificates) {
            var certificateGroup = await GetGroupAsync(groupId, _serviceHost)
                .ConfigureAwait(false);
            var result = await certificateGroup.RevokeCertificatesAsync(
                certificates.ToStackModel()).ConfigureAwait(false);
            return result.ToServiceModel(null);
        }

        /// <inheritdoc/>
        public async Task<X509CertificateModel> CreateIssuerCACertificateAsync(string groupId) {
            var certificateGroup = await GetGroupAsync(groupId, _serviceHost)
                .ConfigureAwait(false);
            var success = await certificateGroup.CreateIssuerCACertificateAsync()
                .ConfigureAwait(false);
            if (success) {
                return certificateGroup.Certificate.ToServiceModel();
            }
            return null;
        }

        /// <inheritdoc/>
        public async Task<X509CertificateModel> SigningRequestAsync(string groupId,
            string applicationUri, byte[] certificateRequest) {
            var certificateGroup = await GetGroupAsync(groupId, _serviceHost)
                .ConfigureAwait(false);
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
            string groupId, string requestId, string applicationUri, string subjectName,
            string[] domainNames, string privateKeyFormat, string privateKeyPassword) {
            var certificateGroup = await GetGroupAsync(groupId, _serviceHost)
                .ConfigureAwait(false);
            var app = new Opc.Ua.Gds.ApplicationRecordDataType {
                ApplicationNames = new LocalizedTextCollection(),
                ApplicationUri = applicationUri
            };
            var keyPair = await certificateGroup.NewKeyPairRequestAsync(
                app, subjectName, domainNames, privateKeyFormat, privateKeyPassword)
                    .ConfigureAwait(false);
            await certificateGroup.ImportCertKeySecret(requestId, keyPair.PrivateKey,
                keyPair.PrivateKeyFormat);
            return keyPair.ToServiceModel();
        }

        /// <inheritdoc/>
        public async Task<X509CertificateCollectionModel> GetIssuerCACertificateVersionsAsync(
            string groupId, bool? withCertificates, string nextPageLink, int? pageSize) {
            // TODO: implement withCertificates
            var certificateGroup = await GetGroupAsync(groupId, _serviceHost)
                .ConfigureAwait(false);
            var (result, nextLink) = await _keyVaultServiceClient.ListCertificateVersionsAsync(
                groupId, null, nextPageLink, pageSize);
            return result.ToServiceModel(nextLink);
        }

        /// <inheritdoc/>
        public async Task<X509CertificateCollectionModel> GetIssuerCACertificateChainAsync(
            string groupId, string thumbPrint = null, string nextPageLink = null, int? pageSize = null) {
            // TODO: implement paging (low priority, only when long chains are expected)
            var certificateGroup = await GetGroupAsync(groupId, _serviceHost)
                .ConfigureAwait(false);
            var cert = await certificateGroup.GetIssuerCACertificateAsync(thumbPrint)
                .ConfigureAwait(false);
            return new X509Certificate2Collection(cert).ToServiceModel(null);
        }

        /// <inheritdoc/>
        public async Task<X509CrlCollectionModel> GetIssuerCACrlChainAsync(string groupId,
            string thumbPrint = null, string nextPageLink = null, int? pageSize = null) {
            // TODO: implement paging (low priority, only when long chains are expected)
            var certificateGroup = await GetGroupAsync(groupId, _serviceHost)
                .ConfigureAwait(false);
            var crl = await certificateGroup.GetIssuerCACrlAsync(thumbPrint)
                .ConfigureAwait(false);
            return new X509CrlCollectionModel {
                Chain = new List<X509CrlModel> { crl.ToServiceModel() }
            };
        }

        /// <inheritdoc/>
        public async Task<byte[]> LoadPrivateKeyAsync(string groupId, string requestId,
            string privateKeyFormat) {
            var certificateGroup = await GetGroupAsync(groupId, _serviceHost)
                .ConfigureAwait(false);
            return await certificateGroup.LoadCertKeySecretAsync(requestId, privateKeyFormat);
        }

        /// <inheritdoc/>
        public async Task AcceptPrivateKeyAsync(string groupId, string requestId) {
            var certificateGroup = await GetGroupAsync(groupId, _serviceHost)
                .ConfigureAwait(false);
            await certificateGroup.AcceptCertKeySecretAsync(requestId);
        }

        /// <inheritdoc/>
        public async Task DeletePrivateKeyAsync(string groupId, string requestId) {
            var certificateGroup = await GetGroupAsync(groupId, _serviceHost)
                .ConfigureAwait(false);
            await certificateGroup.DeleteCertKeySecretAsync(requestId);
        }

        /// <inheritdoc/>
        public async Task<TrustListModel> GetTrustListAsync(string groupId,
            string nextPageLink = null, int? pageSize = null) {
            var trustlist = await _keyVaultServiceClient.GetTrustListAsync(
                groupId, pageSize, nextPageLink);
            return trustlist.ToServiceModel();
        }

        /// <inheritdoc/>
        public Task PurgeAsync(string configId = null, string groupId = null) {
            return _keyVaultServiceClient.PurgeAsync(configId, groupId);
        }

        /// <summary>
        /// Open or create group
        /// </summary>
        /// <param name="groupId"></param>
        /// <param name="serviceHost"></param>
        /// <returns></returns>
        public async Task<KeyVaultCertificateGroup> GetGroupAsync(string groupId,
            string serviceHost) {
            var certificateGroupConfiguration = await GetGroupConfigurationAsync(groupId);
            if (certificateGroupConfiguration == null) {
                throw new ResourceNotFoundException("The certificate group doesn't exist.");
            }
            return new KeyVaultCertificateGroup(_keyVaultServiceClient,
                certificateGroupConfiguration, serviceHost);
        }

        private readonly IVaultConfig _config;
        private readonly IKeyVaultServiceClient _keyVaultServiceClient;
        private readonly ILogger _logger;
        private readonly string _serviceHost;
    }
}
