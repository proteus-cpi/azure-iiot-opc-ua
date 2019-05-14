// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace Microsoft.Azure.IIoT.OpcUa.Vault.Models {

    /// <summary>
    /// Certificate group update model
    /// </summary>
    public sealed class CertificateGroupUpdateModel {

        /// <summary>
        /// The name of the certificate group.
        /// </summary>
        public string Name { get; set; }

        /// <summary>
        /// The subject as distinguished name.
        /// </summary>
        public string SubjectName { get; set; }

        /// <summary>
        /// The certificate type as specified in the OPC UA
        /// spec 1.04.
        /// </summary>
        public CertificateType? CertificateType { get; set; }

        /// <summary>
        /// The certificate lifetime in months.
        /// </summary>
        public ushort? DefaultCertificateLifetime { get; set; }

        /// <summary>
        /// The default certificate key size in bits.
        /// </summary>
        public ushort? DefaultCertificateKeySize { get; set; }

        /// <summary>
        /// The default certificate SHA-2 hash size in bits.
        /// </summary>
        public ushort? DefaultCertificateHashSize { get; set; }

        /// <summary>
        /// The default issuer CA certificate lifetime in months.
        /// </summary>
        public ushort? IssuerCACertificateLifetime { get; set; }

        /// <summary>
        /// The default issuer CA certificate key size in bits.
        /// </summary>
        public ushort? IssuerCACertificateKeySize { get; set; }

        /// <summary>
        /// The default issuer CA certificate key size in bits.
        /// </summary>
        public ushort? IssuerCACertificateHashSize { get; set; }
    }
}
