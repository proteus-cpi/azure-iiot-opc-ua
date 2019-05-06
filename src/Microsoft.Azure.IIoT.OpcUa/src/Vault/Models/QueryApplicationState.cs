// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace Microsoft.Azure.IIoT.OpcUa.Vault.Models {
    using System;
    using Newtonsoft.Json;
    using Newtonsoft.Json.Converters;

    /// <summary>
    /// Query state
    /// </summary>
    [Flags]
    [JsonConverter(typeof(StringEnumConverter))]
    public enum QueryApplicationState : uint {

        /// <summary>
        /// Any state
        /// </summary>
        Any = 0,

        /// <summary>
        /// New
        /// </summary>
        New = 1,

        /// <summary>
        /// Approved
        /// </summary>
        Approved = 2,

        /// <summary>
        /// Rejected
        /// </summary>
        Rejected = 4,

        /// <summary>
        /// Unregistered
        /// </summary>
        Unregistered = 8,

        /// <summary>
        /// Deleted
        /// </summary>
        Deleted = 16
    }
}
