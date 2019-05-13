// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace Microsoft.Azure.IIoT.OpcUa.Registry.Models {
    using Newtonsoft.Json;
    using Newtonsoft.Json.Converters;

    /// <summary>
    /// Application lifecycle events
    /// </summary>
    [JsonConverter(typeof(StringEnumConverter))]
    public enum ApplicationEvent {

        /// <summary>
        /// New
        /// </summary>
        New,

        /// <summary>
        /// New
        /// </summary>
        Updated,

        /// <summary>
        /// Activated
        /// </summary>
        Approved,

        /// <summary>
        /// Rejected
        /// </summary>
        Rejected,

        /// <summary>
        /// Enabled
        /// </summary>
        Enabled,

        /// <summary>
        /// Disabled
        /// </summary>
        Disabled,

        /// <summary>
        /// Unregistered
        /// </summary>
        Unregistered,
    }
}

