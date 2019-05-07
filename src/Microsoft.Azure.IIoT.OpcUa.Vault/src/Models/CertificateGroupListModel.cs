// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace Microsoft.Azure.IIoT.OpcUa.Vault.Models {
    using Newtonsoft.Json;
    using System.Collections.Generic;

    /// <summary>
    /// Create group list model
    /// </summary>
    public sealed class CertificateGroupListModel {

        /// <summary>
        /// Groups
        /// </summary>
        [JsonProperty(PropertyName = "groups")]
        public IList<string> Groups { get; set; }
    }
}
