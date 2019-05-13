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
        /// Called when application state changes
        /// </summary>
        /// <param name="eventType"></param>
        /// <param name="application"></param>
        /// <returns></returns>
        Task OnEventAsync(ApplicationEvent eventType,
            ApplicationInfoModel application);
    }
}
