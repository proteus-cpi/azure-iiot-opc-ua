// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace Microsoft.Azure.IIoT.OpcUa.Vault.Models {
    using Newtonsoft.Json;

    /// <summary>
    /// Trust list api model
    /// </summary>
    public sealed class TrustListModel {

        /// <summary>
        /// Group id
        /// </summary>
        [JsonProperty(PropertyName = "groupId")]
        public string GroupId { get; set; }

        /// <summary>
        /// Issuer certificates
        /// </summary>
        [JsonProperty(PropertyName = "issuerCertificates")]
        public X509CertificateCollectionModel IssuerCertificates { get; set; }

        /// <summary>
        /// Issuer crls
        /// </summary>
        [JsonProperty(PropertyName = "issuerCrls")]
        public X509CrlCollectionModel IssuerCrls { get; set; }

        /// <summary>
        /// Trusted certificates
        /// </summary>
        [JsonProperty(PropertyName = "trustedCertificates")]
        public X509CertificateCollectionModel TrustedCertificates { get; set; }

        /// <summary>
        /// Trusted crls
        /// </summary>
        [JsonProperty(PropertyName = "trustedCrls")]
        public X509CrlCollectionModel TrustedCrls { get; set; }

        /// <summary>
        /// Next page link
        /// </summary>
        [JsonProperty(PropertyName = "nextPageLink")]
        public string NextPageLink { get; set; }
    }
}
