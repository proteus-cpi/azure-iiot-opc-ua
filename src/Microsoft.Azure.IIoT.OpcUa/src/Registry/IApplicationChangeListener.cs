// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace Microsoft.Azure.IIoT.OpcUa.Registry {
    using Microsoft.Azure.IIoT.OpcUa.Registry.Models;
    using System.Threading.Tasks;

    /// <summary>
    /// Application change listener
    /// </summary>
    public interface IApplicationChangeListener {

        /// <summary>
        /// Called when application is added
        /// </summary>
        /// <param name="application"></param>
        /// <returns></returns>
        Task OnApplicationNewAsync(
            ApplicationInfoModel application);

        /// <summary>
        /// Called when application is updated
        /// </summary>
        /// <param name="application"></param>
        /// <returns></returns>
        Task OnApplicationUpdatedAsync(
            ApplicationInfoModel application);

        /// <summary>
        /// Called when application is activated
        /// </summary>
        /// <param name="application"></param>
        /// <returns></returns>
        Task OnApplicationApprovedAsync(
            ApplicationInfoModel application);

        /// <summary>
        /// Called when application is rejected
        /// </summary>
        /// <param name="application"></param>
        /// <returns></returns>
        Task OnApplicationRejectedAsync(
            ApplicationInfoModel application);

        /// <summary>
        /// Called when application is enabled
        /// </summary>
        /// <param name="application"></param>
        /// <returns></returns>
        Task OnApplicationEnabledAsync(
            ApplicationInfoModel application);

        /// <summary>
        /// Called when application is disabled
        /// </summary>
        /// <param name="application"></param>
        /// <returns></returns>
        Task OnApplicationDisabledAsync(
            ApplicationInfoModel application);

        /// <summary>
        /// Called when application is unregistered
        /// </summary>
        /// <param name="application"></param>
        /// <returns></returns>
        Task OnApplicationDeletedAsync(
            ApplicationInfoModel application);
    }
}
