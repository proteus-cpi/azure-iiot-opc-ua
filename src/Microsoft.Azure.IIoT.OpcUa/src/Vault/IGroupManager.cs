// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace Microsoft.Azure.IIoT.OpcUa.Vault {
    using Microsoft.Azure.IIoT.OpcUa.Registry.Models;
    using Microsoft.Azure.IIoT.OpcUa.Vault.Models;
    using System.Threading.Tasks;

    /// <summary>
    /// Manages application group membership
    /// </summary>
    public interface IGroupManager {

        /// <summary>
        /// Assign application to group
        /// </summary>
        /// <param name="applicationId"></param>
        /// <param name="groupId"></param>
        /// <returns></returns>
        Task AssignToGroupAsync(string applicationId,
            string groupId);

        /// <summary>
        /// Remove application from group
        /// </summary>
        /// <param name="applicationId"></param>
        /// <param name="groupId"></param>
        /// <returns></returns>
        Task RemoveFromGroupAsync(string applicationId, 
            string groupId);

        /// <summary>
        /// List all groups the application is assigned to
        /// </summary>
        /// <param name="applicationId"></param>
        /// <param name="nextPageLink"></param>
        /// <param name="maxPageSize"></param>
        /// <returns></returns>
        Task<CertificateGroupListModel> ListGroupsAsync(
            string applicationId, string nextPageLink = null,
            int? maxPageSize = null);

        /// <summary>
        /// List all applications in a group.
        /// </summary>
        /// <param name="groupId"></param>
        /// <param name="nextPageLink"></param>
        /// <param name="maxPageSize"></param>
        /// <returns></returns>
        Task<ApplicationListModel> ListApplicationsAsync(
            string groupId, string nextPageLink = null,
            int? maxPageSize = null);

        /// <summary>
        /// Get application trust list
        /// </summary>
        /// <param name="applicationId"></param>
        /// <param name="groupId"></param>
        /// <returns></returns>
        Task<TrustListModel> GetTrustListAsync(string applicationId,
            string groupId);
    }
}
