// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace Microsoft.Azure.IIoT.OpcUa.Vault {
    using Microsoft.Azure.IIoT.OpcUa.Vault.Models;
    using System.Threading.Tasks;

    /// <summary>
    /// Certificate group manager - create and delete certificate
    /// authorities (i.e. groups) that can be used to create new 
    /// certificates.
    /// </summary>
    public interface ICertificateGroupManager {

        /// <summary>
        /// Create a new certificate group with default settings.
        /// Default settings depend on the chosen certificate type.
        /// </summary>
        /// <param name="request">Create request</param>
        Task<CertificateGroupCreateResultModel> CreateGroupAsync(
            CertificateGroupCreateRequestModel request);

        /// <summary>
        /// Get the configuration for a group Id.
        /// </summary>
        /// <param name="groupId">The group Id</param>
        /// <returns>The configuration</returns>
        Task<CertificateGroupInfoModel> GetGroupAsync(
            string groupId);

        /// <summary>
        /// Update settings of a certificate group.
        /// The update is sanity checked against default policies.
        /// </summary>
        /// <param name="groupId">The group Id</param>
        /// <param name="request">The update request</param>
        /// <returns>The updated group</returns>
        Task UpdateGroupAsync(string groupId,
            CertificateGroupUpdateModel request);

        /// <summary>
        /// Delete a certificate group.
        /// </summary>
        /// <param name="groupId">The group Id</param>
        Task DeleteGroupAsync(string groupId);

        /// <summary>
        /// Get the configuration of all certificate groups.
        /// </summary>
        /// <param name="nextPageLink"></param>
        /// <param name="pageSize"></param>
        /// <returns>The configurations</returns>
        Task<CertificateGroupInfoListModel> ListGroupsAsync(
            string nextPageLink = null, int? pageSize = null);

        /// <summary>
        /// Return the names of the certificate groups in
        /// the store.
        /// </summary>
        /// <param name="nextPageLink"></param>
        /// <param name="pageSize"></param>
        /// <returns>The certificate group ids</returns>
        Task<CertificateGroupListModel> ListGroupIdsAsync(
            string nextPageLink = null, int? pageSize = null);
    }
}
