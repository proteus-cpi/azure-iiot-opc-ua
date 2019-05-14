// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace Microsoft.Azure.IIoT.OpcUa.Vault.Services {
    using Microsoft.Azure.IIoT.Exceptions;
    using Microsoft.Azure.IIoT.OpcUa.Vault.Models;
    using Microsoft.Azure.IIoT.OpcUa.Vault.Services.Models;
    using Microsoft.Azure.IIoT.Storage;
    using Serilog;
    using System;
    using System.Linq;
    using System.Threading.Tasks;

    /// <summary>
    /// Certificate Group database
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
        }

        /// <inheritdoc/>
        public async Task<CertificateGroupInfoModel> GetGroupAsync(
            string groupId) {
            if (string.IsNullOrEmpty(groupId)) {
                throw new ArgumentNullException(nameof(groupId),
                    "The group id must be provided");
            }
            var document = await _groups.GetAsync<CertificateGroupDocument>(groupId);
            if (document == null) {
                throw new ResourceNotFoundException("No such group");
            }
            return document.Value.ToServiceModel();
        }

        /// <inheritdoc/>
        public async Task UpdateGroupAsync(string groupId, CertificateGroupUpdateModel request) {
            if (request == null) {
                throw new ArgumentNullException(nameof(request),
                    "The application must be provided");
            }
            if (string.IsNullOrEmpty(groupId)) {
                throw new ArgumentNullException(nameof(groupId),
                    "The group id must be provided");
            }
            while (true) {
                var document = await _groups.GetAsync<CertificateGroupDocument>(groupId);
                if (document == null) {
                    throw new ResourceNotFoundException("Group does not exist");
                }
                var group = document.Value.Clone().ToServiceModel();
                group.Patch(request);
                try {
                    var result = await _groups.ReplaceAsync(document, group.ToDocumentModel());
                    break;
                }
                catch (ResourceOutOfDateException) {
                    continue;
                }
            }
        }

        /// <inheritdoc/>
        public async Task<CertificateGroupCreateResultModel> CreateGroupAsync(
            CertificateGroupCreateRequestModel request) {
            if (request == null) {
                throw new ArgumentNullException(nameof(request));
            }
            var config = CertificateGroupInfoModelEx.GetDefaultGroupConfiguration(request);
            var document = config.ToDocumentModel();
            var result = await _groups.AddAsync(document);
            return new CertificateGroupCreateResultModel {
                Id = document.GroupId
            };
        }

        /// <inheritdoc/>
        public async Task<CertificateGroupInfoListModel> ListGroupsAsync(
            string nextPageLink, int? pageSize) {
            var client = _groups.OpenSqlClient();
            var query = nextPageLink != null ?
                client.Continue<CertificateGroupDocument>(nextPageLink, pageSize) :
                client.Query<CertificateGroupDocument>(
                    "SELECT * FROM Groups g WHERE " +
        $"g.{nameof(CertificateGroupDocument.ClassType)} = '{CertificateGroupDocument.ClassTypeName}'",
                null, pageSize);
            // Read results
            var results = await query.ReadAsync();
            return new CertificateGroupInfoListModel {
                Groups = results.Select(r => r.Value.ToServiceModel()).ToList(),
                NextPageLink = query.ContinuationToken
            };
        }

        /// <inheritdoc/>
        public async Task<CertificateGroupListModel> ListGroupIdsAsync(
            string nextPageLink, int? pageSize) {
            var client = _groups.OpenSqlClient();
            var query = nextPageLink != null ?
                client.Continue<string>(nextPageLink, pageSize) :
                client.Query<string>(
                    $"SELECT g.id FROM Groups g WHERE " +
        $"g.{nameof(CertificateGroupDocument.ClassType)} = '{CertificateGroupDocument.ClassTypeName}'",
                null, pageSize);
            // Read results
            var results = await query.ReadAsync();
            return new CertificateGroupListModel {
                Groups = results.Select(r => r.Value).ToList(),
                NextPageLink = query.ContinuationToken
            };
        }

        /// <inheritdoc/>
        public async Task DeleteGroupAsync(string groupId) {
            if (string.IsNullOrEmpty(groupId)) {
                throw new ArgumentNullException(nameof(groupId),
                    "The application id must be provided");
            }
            while (true) {
                var document = await _groups.GetAsync<CertificateGroupDocument>(groupId);
                if (document == null) {
                    throw new ResourceNotFoundException(
                        "A record with the specified group id does not exist.");
                }
                try {
                    // Try delete
                    await _groups.DeleteAsync(document);
                    break;
                }
                catch (ResourceOutOfDateException) {
                    continue;
                }
            }
        }

        private readonly ILogger _logger;
        private readonly IDocuments _groups;
    }
}
