// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace Microsoft.Azure.IIoT.OpcUa.Vault {
    using Microsoft.Azure.IIoT.OpcUa.Registry.Models;
    using Microsoft.Azure.IIoT.OpcUa.Vault.Models;
    using System.Threading.Tasks;

    /// <summary>
    /// Manages application trust zones. A trust zone 
    /// is a group of applications and servers that trust 
    /// each other.  
    /// </summary>
    public interface ITrustZoneManager {

        /// <summary>
        /// Assign application to zone.  If the zone does
        /// not exist the zone is created.
        /// </summary>
        /// <param name="applicationId"></param>
        /// <param name="zoneId"></param>
        /// <returns></returns>
        Task AddApplicationAsync(string zoneId,
            string applicationId);

        /// <summary>
        /// Remove application from speocified zone.  If
        /// zone is not specified, removes application
        /// from all zones.  A zone is deleted if it
        /// does not have any applications.
        /// </summary>
        /// <param name="applicationId"></param>
        /// <param name="zoneId"></param>
        /// <returns></returns>
        Task RemoveApplicationAsync(string applicationId, 
            string zoneId = null);

        /// <summary>
        /// Quarantine application - disables all
        /// membership of an application in all zones.
        /// </summary>
        /// <param name="applicationId"></param>
        /// <param name="enable"></param>
        /// <returns></returns>
        Task QuarantineApplicationAsync(string applicationId,
            bool enable);

        /// <summary>
        /// List all zones the application is assigned to.
        /// </summary>
        /// <param name="applicationId"></param>
        /// <param name="nextPageLink"></param>
        /// <param name="maxPageSize"></param>
        /// <returns></returns>
        Task<CertificateGroupListModel> ListZonesAsync(
            string applicationId, string nextPageLink = null,
            int? maxPageSize = null);

        /// <summary>
        /// List all non-quarantined applications in a zone.
        /// </summary>
        /// <param name="zoneId"></param>
        /// <param name="nextPageLink"></param>
        /// <param name="maxPageSize"></param>
        /// <returns></returns>
        Task<ApplicationListModel> ListApplicationsAsync(
            string zoneId, string nextPageLink = null,
            int? maxPageSize = null);

        /// <summary>
        /// Get trust list of the zone with the specified type - 
        /// optionally filtered on a zone.
        /// </summary>
        /// <param name="applicationId"></param>
        /// <param name="trustListType"></param>
        /// <param name="zoneId"></param>
        /// <returns></returns>
        Task<TrustListModel> GetTrustListAsync(string applicationId,
            CertificateType trustListType, string zoneId = null);

        /// <summary>
        /// Delete a specific zone and all trust relationships
        /// in the zone.
        /// </summary>
        /// <param name="zoneId"></param>
        /// <returns></returns>
        Task DeleteZoneAsync(string zoneId);
    }
}
