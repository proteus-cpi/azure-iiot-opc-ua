// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace Microsoft.Azure.IIoT.OpcUa.Registry {
    using Microsoft.Azure.IIoT.OpcUa.Registry.Models;
    using System.Threading.Tasks;

    /// <summary>
    /// Endpoint change listener
    /// </summary>
    public interface IEndpointChangeListener {

        /// <summary>
        /// Called when endpoint registry changes
        /// </summary>
        /// <param name="eventType"></param>
        /// <param name="endpoint"></param>
        /// <returns></returns>
        Task OnEventAsync(EndpointEvent eventType,
            EndpointRegistrationModel endpoint);
    }
}
