// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace Microsoft.Azure.IIoT.OpcUa.Vault.Models {
    using System;
    using Newtonsoft.Json;
    using Newtonsoft.Json.Converters;

    /// <summary>
    /// Application type query
    /// </summary>
    [Flags]
    [JsonConverter(typeof(StringEnumConverter))]
    public enum QueryApplicationType {
        /// <summary>
        /// Any type
        /// </summary>
        Any = 0,
        /// <summary>
        /// Server
        /// </summary>
        Server = 1,
        /// <summary>
        /// Client
        /// </summary>
        Client = 2,
    }
}

