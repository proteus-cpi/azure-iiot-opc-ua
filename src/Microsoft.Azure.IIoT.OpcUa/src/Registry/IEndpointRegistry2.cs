﻿// ------------------------------------------------------------
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
    }
}
