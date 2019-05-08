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
        public string GroupId { get; set; }

        /// <summary>
        /// Issuer certificates
        /// </summary>
        public X509CertificateCollectionModel IssuerCertificates { get; set; }

        /// <summary>
        /// Issuer crls
        /// </summary>
        public X509CrlCollectionModel IssuerCrls { get; set; }

        /// <summary>
        /// Trusted certificates
        /// </summary>
        public X509CertificateCollectionModel TrustedCertificates { get; set; }

        /// <summary>
        /// Trusted crls
        /// </summary>
        public X509CrlCollectionModel TrustedCrls { get; set; }

        /// <summary>
        /// Next page link
        /// </summary>
        public string NextPageLink { get; set; }
    }
}
