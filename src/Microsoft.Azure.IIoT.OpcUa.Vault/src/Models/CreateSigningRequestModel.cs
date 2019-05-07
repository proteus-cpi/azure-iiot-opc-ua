// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace Microsoft.Azure.IIoT.OpcUa.Vault.Models {
    using Newtonsoft.Json;

    /// <summary>
    /// Signing request
    /// </summary>
    public sealed class CreateSigningRequestModel {

        /// <summary>
        /// Application id
        /// </summary>
        [JsonProperty(PropertyName = "applicationId")]
        public string ApplicationId { get; set; }

        /// <summary>
        /// Certificate group id
        /// </summary>
        [JsonProperty(PropertyName = "certificateGroupId")]
        public string CertificateGroupId { get; set; }

        /// <summary>
        /// Type
        /// </summary>
        [JsonProperty(PropertyName = "certificateTypeId")]
        public string CertificateTypeId { get; set; }

        /// <summary>
        /// Request string
        /// </summary>
        [JsonProperty(PropertyName = "certificateRequest")]
        public string CertificateRequest { get; set; }
    }
}
