// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace Microsoft.Azure.IIoT.OpcUa.Vault.Models {
    using Newtonsoft.Json;
    using System.Collections.Generic;

    /// <summary>
    /// Query applications
    /// </summary>
    public sealed class QueryApplicationsRequestModel {

        /// <summary>
        /// Application name
        /// </summary>
        [JsonProperty(PropertyName = "applicationName")]
        public string ApplicationName { get; set; }

        /// <summary>
        /// Application uri
        /// </summary>
        [JsonProperty(PropertyName = "applicationUri")]
        public string ApplicationUri { get; set; }

        /// <summary>
        /// Application type
        /// </summary>
        [JsonProperty(PropertyName = "applicationType")]
        public QueryApplicationType ApplicationType { get; set; }

        /// <summary>
        /// Product uri
        /// </summary>
        [JsonProperty(PropertyName = "productUri")]
        public string ProductUri { get; set; }

        /// <summary>
        /// Server capabilities
        /// </summary>
        [JsonProperty(PropertyName = "serverCapabilities")]
        public IList<string> ServerCapabilities { get; set; }

        /// <summary>
        /// Application state
        /// </summary>
        [JsonProperty(PropertyName = "applicationState")]
        public QueryApplicationState? ApplicationState { get; set; }
    }
}
