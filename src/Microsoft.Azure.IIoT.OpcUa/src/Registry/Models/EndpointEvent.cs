// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace Microsoft.Azure.IIoT.OpcUa.Registry.Models {
    using Newtonsoft.Json;
    using Newtonsoft.Json.Converters;

    /// <summary>
    /// Endpoint registration event
    /// </summary>
    [JsonConverter(typeof(StringEnumConverter))]
    public enum EndpointEvent {

        /// <summary>
        /// New
        /// </summary>
        Added,

        /// <summary>
        /// Activated
        /// </summary>
        Activated,

        /// <summary>
        /// Rejected
        /// </summary>
        Deactivated,

        /// <summary>
        /// Deleted
        /// </summary>
        Deleted
    }
}
