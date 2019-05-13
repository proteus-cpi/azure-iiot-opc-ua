// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------


namespace Microsoft.Azure.IIoT.OpcUa.Vault.Services {
    using Microsoft.Azure.IIoT.OpcUa.Vault.Models;
    using Microsoft.Azure.IIoT.Storage;
    using Microsoft.Azure.IIoT.Storage.Default;
    using Serilog;
    using System;
    using System.Threading.Tasks;

    /// <summary>
    /// Group database
    /// </summary>
    public sealed class GroupDatabase : IGroupRegistry {

        /// <summary>
        /// Create groups database
        /// </summary>
        /// <param name="db"></param>
        /// <param name="logger"></param>
        public GroupDatabase(IItemContainerFactory db, ILogger logger) {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            if (db == null) {
                throw new ArgumentNullException(nameof(db));
            }

            var container = db.OpenAsync().Result;
            _groups = container.AsDocuments();
            _index = new ContainerIndex(container);
        }


        /// <inheritdoc/>
        public Task<CertificateGroupInfoModel> DeleteGroupAsync(
            string groupId) {
            throw new NotImplementedException();
        }

        /// <inheritdoc/>
        public Task<CertificateGroupInfoModel> GetGroupAsync(
            string groupId) {
            throw new NotImplementedException();
        }

        /// <inheritdoc/>
        public Task<CertificateGroupInfoModel> UpdateGroupAsync(
            string groupId, CertificateGroupInfoModel config) {
            throw new NotImplementedException();
        }
        /// <inheritdoc/>
        public Task<CertificateGroupInfoModel> CreateGroupAsync(
            string groupId, string subject, CertificateType certType) {
            throw new NotImplementedException();
        }
        /// <inheritdoc/>
        public Task<CertificateGroupInfoListModel> ListGroupsAsync(
            string nextPageLink, int? pageSize) {
            throw new NotImplementedException();
        }
        /// <inheritdoc/>
        public Task<CertificateGroupListModel> ListGroupIdsAsync(
            string nextPageLink, int? pageSize) {
            throw new NotImplementedException();
        }

        private readonly ILogger _logger;
        private readonly IDocuments _groups;
        private readonly ContainerIndex _index;
    }
}
