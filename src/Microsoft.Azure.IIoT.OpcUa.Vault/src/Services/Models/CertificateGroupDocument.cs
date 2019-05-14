// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace Microsoft.Azure.IIoT.OpcUa.Vault.Services.Models {
    using Newtonsoft.Json;
    using System;

    /// <summary>
    /// Group document
    /// </summary>
    [Serializable]
    public sealed class CertificateGroupDocument {

        /// <summary>
        /// The id of the group.
        /// </summary>
        [JsonProperty(PropertyName = "id")]
        public string GroupId { get; set; }

        /// <summary>
        /// The name of the group.
        /// </summary>
        public string Name { get; set; }

        /// <summary>
        /// Etag
        /// </summary>
        [JsonProperty(PropertyName = "_etag")]
        public string ETag { get; set; }

        /// <summary>
        /// Document type
        /// </summary>
        public string ClassType { get; set; } = ClassTypeName;

        /// <summary>
        /// The certificate type as specified in the OPC UA
        /// spec 1.04.
        /// </summary>
        public string CertificateType { get; set; }

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

        /// <inheritdoc/>

        public static readonly string ClassTypeName = "Group";
    }
}
