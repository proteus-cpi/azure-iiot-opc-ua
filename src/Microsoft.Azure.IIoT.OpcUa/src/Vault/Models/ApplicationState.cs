// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace Microsoft.Azure.IIoT.OpcUa.Vault.Models {
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
        New = 0,

        /// <summary>
        /// Activated
        /// </summary>
        Approved = 1,

        /// <summary>
        /// Rejected
        /// </summary>
        Rejected = 2,

        /// <summary>
        /// Unregistered
        /// </summary>
        Unregistered = 3,

        /// <summary>
        /// Deleted
        /// </summary>
        Deleted = 4
    }
}

