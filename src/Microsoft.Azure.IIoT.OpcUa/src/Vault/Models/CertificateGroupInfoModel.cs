// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace Microsoft.Azure.IIoT.OpcUa.Vault.Models {

    /// <summary>
    /// Certificate group model
    /// </summary>
    public sealed class CertificateGroupInfoModel {

        /// <summary>
        /// The name of the certificate group, ofter referred
        /// to as group id.
        /// </summary>
        public string Id { get; set; }

        /// <summary>
        /// The certificate type as specified in the OPC UA
        /// spec 1.04.
        /// </summary>
        public CertificateType CertificateType { get; set; }

        /// <summary>
        /// The subject as distinguished name.
        /// </summary>
        public string SubjectName { get; set; }

        /// <summary>
        /// The default certificate lifetime in months.
        /// Default: 24 months.
        /// </summary>
        public ushort DefaultCertificateLifetime { get; set; }

        /// <summary>
        /// The default certificate key size in bits.
        /// Allowed values: 2048, 3072, 4096
        /// </summary>
        public ushort DefaultCertificateKeySize { get; set; }

        /// <summary>
        /// The default certificate SHA-2 hash size in bits.
        /// Allowed values: 256 (default), 384, 512
        /// </summary>
        public ushort DefaultCertificateHashSize { get; set; }

        /// <summary>
        /// The default issuer CA certificate lifetime in months.
        /// Default: 60 months.
        /// </summary>
        public ushort IssuerCACertificateLifetime { get; set; }

        /// <summary>
        /// The default issuer CA certificate key size in bits.
        /// Allowed values: 2048, 3072, 4096
        /// </summary>
        public ushort IssuerCACertificateKeySize { get; set; }

        /// <summary>
        /// The default issuer CA certificate key size in bits.
        /// Allowed values: 2048, 3072, 4096
        /// </summary>
        public ushort IssuerCACertificateHashSize { get; set; }

        /// <summary>
        /// The endpoint URL for the CRL Distributionpoint in
        /// the Issuer CA certificate.
        /// The names %servicehost%, %serial% and %group% are
        /// replaced with cert values.
        /// </summary>
        public string IssuerCACrlDistributionPoint { get; set; }

        /// <summary>
        /// The endpoint URL for the Issuer CA Authority
        /// Information Access.
        /// The names %servicehost%, %serial% and %group% are
        /// replaced with cert values.
        /// </summary>
        public string IssuerCAAuthorityInformationAccess { get; set; }
    }
}
