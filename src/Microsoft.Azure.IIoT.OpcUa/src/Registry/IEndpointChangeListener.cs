// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace Microsoft.Azure.IIoT.OpcUa.Registry {
    using Microsoft.Azure.IIoT.OpcUa.Registry.Models;
    using System.Threading.Tasks;

    /// <summary>
    /// Notified when an endpoint configuration changes
    /// </summary>
    public interface IEndpointChangeListener {

        /// <summary>
        /// New endpoint
        /// </summary>
        /// <param name="endpoint"></param>
        /// <returns></returns>
        Task OnEndpointNewAsync(
            EndpointInfoModel endpoint);

        /// <summary>
        /// New endpoint
        /// </summary>
        /// <param name="endpoint"></param>
        /// <returns></returns>
        Task OnEndpointActivatedAsync(
            EndpointInfoModel endpoint);

        /// <summary>
        /// New endpoint
        /// </summary>
        /// <param name="endpoint"></param>
        /// <returns></returns>
        Task OnEndpointDeactivatedAsync(
            EndpointInfoModel endpoint);

        /// <summary>
        /// New endpoint
        /// </summary>
        /// <param name="endpoint"></param>
        /// <returns></returns>
        Task OnEndpointUpdatedAsync(
            EndpointInfoModel endpoint);

        /// <summary>
        /// New endpoint
        /// </summary>
        /// <param name="endpoint"></param>
        /// <returns></returns>
        Task OnEndpointDeletedAsync(
            EndpointInfoModel endpoint);
    }
}
