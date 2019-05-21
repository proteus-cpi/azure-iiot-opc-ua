// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace Microsoft.Azure.IIoT.OpcUa.Registry {
    using Microsoft.Azure.IIoT.OpcUa.Registry.Models;
    using System.Collections.Generic;
    using System.Threading.Tasks;

    /// <summary>
    /// Extended endpoint registry
    /// </summary>
    public interface IEndpointRegistry2 : IEndpointRegistry {

        /// <summary>
        /// Get application endpoints
        /// </summary>
        /// <param name="applicationId"></param>
        /// <param name="includeDeleted"></param>
        /// <param name="filterInactiveTwins"></param>
        /// <returns></returns>
        Task<IEnumerable<EndpointInfoModel>> GetApplicationEndpoints(string applicationId,
            bool includeDeleted = false, bool filterInactiveTwins = false);

        /// <summary>
        /// Add new endpoints, or merge newly found endpoints with the ones 
        /// under the specified application id if id is not null.
        /// </summary>
        /// <param name="supervisorId"></param>
        /// <param name="context"></param>
        /// <param name="found"></param>
        /// <param name="applicationId"></param>
        /// <param name="hardDelete"></param>
        /// <returns></returns>
        Task ProcessDiscoveryEventsAsync(string supervisorId, IEnumerable<EndpointInfoModel> found,
            DiscoveryResultModel context, string applicationId = null, bool hardDelete = false);
    }
}
