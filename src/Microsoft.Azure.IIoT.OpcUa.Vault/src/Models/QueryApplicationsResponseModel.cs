// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace Microsoft.Azure.IIoT.OpcUa.Vault.Models {
    using Newtonsoft.Json;
    using System.Collections.Generic;

    /// <summary>
    /// Application query response
    /// </summary>
    public sealed class QueryApplicationsResponseModel {

        /// <summary>
        /// Found applications
        /// </summary>
        [JsonProperty(PropertyName = "applications")]
        public IList<ApplicationRecordModel> Applications { get; set; }

        /// <summary>
        /// Next page
        /// </summary>
        [JsonProperty(PropertyName = "nextPageLink")]
        public string NextPageLink { get; set; }
    }
}
