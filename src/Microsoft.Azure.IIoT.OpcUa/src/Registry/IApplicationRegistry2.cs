// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace Microsoft.Azure.IIoT.OpcUa.Registry {
    using Microsoft.Azure.IIoT.OpcUa.Registry.Models;
    using System.Collections.Generic;
    using System.Threading.Tasks;

    /// <summary>
    /// Application Database interface.
    /// </summary>
    public interface IApplicationRegistry2 : IApplicationRegistry {

        /// <summary>
        /// Disable the application. Does not remove the application
        /// from the database.
        /// </summary>
        /// <param name="applicationId">The applicationId</param>
        /// <returns></returns>
        Task DisableApplicationAsync(string applicationId);

        /// <summary>
        /// Re-enable a potentially disabled application.
        /// </summary>
        /// <param name="applicationId">The applicationId</param>
        /// <returns></returns>
        Task EnableApplicationAsync(string applicationId);

        /// <summary>
        /// Query for Applications sorted by ID.
        /// This query implements the search parameters required for the
        /// OPC UA GDS server QueryServers/QueryApplications API.
        /// </summary>
        /// <param name="request">Query</param>
        /// <returns></returns>
        Task<QueryApplicationsByIdResultModel> QueryApplicationsByIdAsync(
            QueryApplicationsByIdRequestModel request);

        /// <summary>
        /// Merge applications and endpoints
        /// </summary>
        /// <param name="siteId"></param>
        /// <param name="supervisorId"></param>
        /// <param name="result"></param>
        /// <param name="events"></param>
        /// <returns></returns>
        Task ProcessDiscoveryEventsAsync(string siteId, string supervisorId,
            DiscoveryResultModel result, IEnumerable<DiscoveryEventModel> events);
    }
}
