// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace Microsoft.Azure.IIoT.OpcUa.Vault.Models {
    using Newtonsoft.Json;
    using System.Collections.Generic;

    /// <summary>
    /// Configuration collection model
    /// </summary>
    public sealed class CertificateGroupConfigurationCollectionModel {

        /// <summary>
        /// Groups
        /// </summary>
        [JsonProperty(PropertyName = "groups")]
        public IList<CertificateGroupConfigurationModel> Groups { get; set; }
    }
}
