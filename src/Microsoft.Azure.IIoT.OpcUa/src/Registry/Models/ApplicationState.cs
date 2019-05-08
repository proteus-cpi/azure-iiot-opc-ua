// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace Microsoft.Azure.IIoT.OpcUa.Registry.Models {
    using Newtonsoft.Json;
    using Newtonsoft.Json.Converters;

    /// <summary>
    /// State of the application
    /// </summary>
    [JsonConverter(typeof(StringEnumConverter))]
    public enum ApplicationState {

        /// <summary>
        /// New
        /// </summary>
        New,

        /// <summary>
        /// Activated
        /// </summary>
        Approved,

        /// <summary>
        /// Rejected
        /// </summary>
        Rejected,

        /// <summary>
        /// Unregistered
        /// </summary>
        Unregistered,

        /// <summary>
        /// Deleted
        /// </summary>
        Deleted
    }
}

