// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace Microsoft.Azure.IIoT.OpcUa.Vault.Models {
    using Newtonsoft.Json;
    using System.Collections.Generic;
    using System.ComponentModel.DataAnnotations;

    /// <summary>
    /// Certificate request record model
    /// </summary>
    public sealed class CertificateRequestRecordModel {

        /// <summary>
        /// Request id
        /// </summary>
        [JsonProperty(PropertyName = "requestId")]
        public string RequestId { get; set; }

        /// <summary>
        /// Application id
        /// </summary>
        [JsonProperty(PropertyName = "applicationId")]
        public string ApplicationId { get; set; }

        /// <summary>
        /// Request state
        /// </summary>
        [JsonProperty(PropertyName = "state")]
        [Required]
        public CertificateRequestState State { get; }

        /// <summary>
        /// Certificate group
        /// </summary>
        [JsonProperty(PropertyName = "certificateGroupId")]
        public string CertificateGroupId { get; set; }

        /// <summary>
        /// Type
        /// </summary>
        [JsonProperty(PropertyName = "certificateTypeId")]
        public string CertificateTypeId { get; set; }

        /// <summary>
        /// Is Signing request
        /// </summary>
        [JsonProperty(PropertyName = "signingRequest")]
        [Required]
        public bool SigningRequest { get; }

        /// <summary>
        /// Subject
        /// </summary>
        [JsonProperty(PropertyName = "subjectName")]
        public string SubjectName { get; set; }

        /// <summary>
        /// Domain names
        /// </summary>
        [JsonProperty(PropertyName = "domainNames")]
        public IList<string> DomainNames { get; set; }

        /// <summary>
        /// Private key format to return
        /// </summary>
        [JsonProperty(PropertyName = "privateKeyFormat")]
        public string PrivateKeyFormat { get; set; }
    }
}
