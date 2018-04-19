﻿// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace Microsoft.Azure.IoTSolutions.OpcTwin.EdgeService.v1 {
    using Newtonsoft.Json.Linq;
    using System.Threading.Tasks;

    /// <summary>
    /// V1 supervisor settings
    /// </summary>
    public interface IOpcUaSupervisorSettings {

        /// <summary>
        /// Update list of managed devices
        /// </summary>
        /// <param name="endpointId"></param>
        /// <param name="secret"></param>
        /// <returns></returns>
        Task SetAsync(string endpointId, JToken secret);

        /// <summary>
        /// Called based on the reported type property
        /// </summary>
        /// <param name="value"></param>
        /// <returns></returns>
        Task SetTypeAsync(string value);

        /// <summary>
        /// Called based on the reported connected
        /// property.
        /// </summary>
        /// <param name="value"></param>
        /// <returns></returns>
        Task SetConnectedAsync(bool value);

        /// <summary>
        /// Enable or disable discovery on supervisor
        /// </summary>
        /// <param name="modeToken"></param>
        /// <returns></returns>
        Task SetDiscoveryAsync(JToken modeToken);

        /// <summary>
        /// Update discovery configuration when changed.
        /// </summary>
        /// <param name="config"></param>
        /// <returns></returns>
        Task SetDiscoveryConfigAsync(JToken config);
    }
}