// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace Microsoft.Azure.IIoT.OpcUa.Vault.Models {
    using Newtonsoft.Json;
    using Newtonsoft.Json.Converters;

    /// <summary>
    /// The application database status when compared to
    /// the registry.
    /// </summary>
    [JsonConverter(typeof(StringEnumConverter))]
    public enum RegistryApplicationStatusType {

        /// <summary>
        /// The Application Id is not known in the registry.
        /// </summary>
        Unknown,

        /// <summary>
        /// The application and registry state are up to
        /// date and ok.
        /// </summary>
        Ok,

        /// <summary>
        /// The registry contains a new application.
        /// </summary>
        New,

        /// <summary>
        /// The registry contains updates compared to the
        /// application database.
        /// </summary>
        Update
    }
}
