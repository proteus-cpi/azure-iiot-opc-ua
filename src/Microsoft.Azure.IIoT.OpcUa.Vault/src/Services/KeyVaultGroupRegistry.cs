// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------


namespace Microsoft.Azure.IIoT.OpcUa.Vault.Services {
    using Microsoft.Azure.IIoT.OpcUa.Vault.KeyVault;
    using Microsoft.Azure.IIoT.OpcUa.Vault.KeyVault.Clients;
    using Microsoft.Azure.IIoT.OpcUa.Vault.Models;
    using Microsoft.Azure.IIoT.Storage;
    using Microsoft.Azure.KeyVault.Models;
    using Newtonsoft.Json;
    using Serilog;
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Net;
    using System.Threading.Tasks;

    /// <summary>
    /// The Key Vault implementation group registry (legacy)
    /// </summary>
    public sealed class KeyVaultGroupRegistry : IGroupRegistry {

        /// <summary>
        /// Create vault client
        /// </summary>
        /// <param name="keyVault"></param>
        /// <param name="logger"></param>
        public KeyVaultGroupRegistry(IKeyValueStore keyVault, ILogger logger) {
            _keyVault = keyVault ?? throw new ArgumentNullException(nameof(keyVault));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        /// <inheritdoc/>
        public async Task<CertificateGroupListModel> ListGroupIdsAsync(
            string nextPageLink, int? pageSize) {
            var json = await _keyVault.GetKeyValueAsync(kGroupKey).ConfigureAwait(false);
            var certificateGroupCollection =
                JsonConvert.DeserializeObject<List<CertificateGroupInfoModel>>(json);
            var groups = certificateGroupCollection.Select(cg => cg.Id).ToList();
            return new CertificateGroupListModel { Groups = groups };
        }

        /// <inheritdoc/>
        public async Task<CertificateGroupInfoModel> GetGroupAsync(
            string groupId) {
            var json = await _keyVault.GetKeyValueAsync(kGroupKey).ConfigureAwait(false);
            var certificateGroupCollection =
                JsonConvert.DeserializeObject<List<CertificateGroupInfoModel>>(json);
            return certificateGroupCollection
                .SingleOrDefault(cg => groupId.EqualsIgnoreCase(cg.Id));
        }

        /// <inheritdoc/>
        public async Task<CertificateGroupInfoModel> UpdateGroupAsync(
            string groupId, CertificateGroupInfoModel config) {

            // TODO: configuration should not have id
            if (groupId.ToLower() != config.Id.ToLower()) {
                throw new ArgumentException("groupid doesn't match config groupId");
            }

            var json = await _keyVault.GetKeyValueAsync(kGroupKey).ConfigureAwait(false);
            var certificateGroupCollection =
                JsonConvert.DeserializeObject<List<CertificateGroupInfoModel>>(json);

            var original = certificateGroupCollection
                .SingleOrDefault(cg => groupId.EqualsIgnoreCase(cg.Id));
            if (original == null) {
                throw new ArgumentException("invalid groupid");
            }

            config.ValidateConfiguration();

            var index = certificateGroupCollection.IndexOf(original);
            certificateGroupCollection[index] = config;
            json = JsonConvert.SerializeObject(certificateGroupCollection);
            // update config
            json = await _keyVault.SetKeyValueAsync(kGroupKey, json)
                .ConfigureAwait(false);
            // read it back to verify
            certificateGroupCollection =
                JsonConvert.DeserializeObject<List<CertificateGroupInfoModel>>(json);
            return certificateGroupCollection.SingleOrDefault(
                cg => groupId.EqualsIgnoreCase(cg.Id));
        }

        /// <inheritdoc/>
        public async Task<CertificateGroupInfoModel> CreateGroupAsync(
            string groupId, string subject, CertificateType certType) {
            var config = KeyVaultCertificateGroup.DefaultConfiguration(groupId, subject, certType);
            if (groupId.ToLower() != config.Id.ToLower()) {
                throw new ArgumentException("groupid doesn't match config groupId");
            }

            string json;
            IList<CertificateGroupInfoModel> certificateGroupCollection =
                new List<CertificateGroupInfoModel>();
            try {
                json = await _keyVault.GetKeyValueAsync(kGroupKey)
                    .ConfigureAwait(false);
                certificateGroupCollection =
                    JsonConvert.DeserializeObject<List<CertificateGroupInfoModel>>(json);
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

            config.ValidateConfiguration();

            certificateGroupCollection.Add(config);
            json = JsonConvert.SerializeObject(certificateGroupCollection);

            // TODO: Write JSON of secret "groups" - throw resource not found if not found
            // update config
            json = await _keyVault.SetKeyValueAsync(kGroupKey, json)
                .ConfigureAwait(false);
            // read it back to verify
            certificateGroupCollection =
                JsonConvert.DeserializeObject<List<CertificateGroupInfoModel>>(json);
            return certificateGroupCollection
                .SingleOrDefault(cg => groupId.EqualsIgnoreCase(cg.Id));
        }

        /// <inheritdoc/>
        public async Task<CertificateGroupInfoListModel> ListGroupsAsync(
            string nextPageLink, int? pageSize) {
            var json = await _keyVault.GetKeyValueAsync(kGroupKey).ConfigureAwait(false);
            var groups = JsonConvert.DeserializeObject<List<CertificateGroupInfoModel>>(json);
            return new CertificateGroupInfoListModel { Groups = groups };
        }

        /// <inheritdoc/>
        public Task<CertificateGroupInfoModel> DeleteGroupAsync(string groupId) {
            throw new NotImplementedException();
        }

        private const string kGroupKey = "groups";
        private readonly IKeyValueStore _keyVault;
        private readonly ILogger _logger;
    }
}
