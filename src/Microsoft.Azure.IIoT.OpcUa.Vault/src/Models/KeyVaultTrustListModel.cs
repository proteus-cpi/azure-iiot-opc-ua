// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------


namespace Microsoft.Azure.IIoT.OpcUa.Vault.Models {
    using Opc.Ua;
    using System.Collections.Generic;
    using System.Security.Cryptography.X509Certificates;

    /// <summary>
    /// Trust list model
    /// </summary>
    public class KeyVaultTrustListModel {

        /// <summary>
        /// Group name
        /// </summary>
        public string Group { get; }

        /// <summary>
        /// Issuer certificates
        /// </summary>
        public X509Certificate2Collection IssuerCertificates { get; set; }

        /// <summary>
        /// Issuer crls
        /// </summary>
        public IList<X509CRL> IssuerCrls { get; set; }

        /// <summary>
        /// Trusted certificates
        /// </summary>
        public X509Certificate2Collection TrustedCertificates { get; set; }

        /// <summary>
        /// Trusted crls
        /// </summary>
        public IList<X509CRL> TrustedCrls { get; set; }

        /// <summary>
        /// Next page
        /// </summary>
        public string NextPageLink { get; set; }

        /// <summary>
        /// Create key vault trust list model
        /// </summary>
        /// <param name="id"></param>
        public KeyVaultTrustListModel(string id) {
            Group = id;
            IssuerCertificates = new X509Certificate2Collection();
            IssuerCrls = new List<X509CRL>();
            TrustedCertificates = new X509Certificate2Collection();
            TrustedCrls = new List<X509CRL>();
            NextPageLink = null;
        }
    }
}
