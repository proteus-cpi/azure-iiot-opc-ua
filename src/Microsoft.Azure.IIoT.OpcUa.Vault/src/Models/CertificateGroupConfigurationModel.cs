// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------


namespace Microsoft.Azure.IIoT.OpcUa.Vault.Models {
    using Newtonsoft.Json;

    /// <summary>
    /// Certificate group model
    /// </summary>
    public sealed class CertificateGroupConfigurationModel {

        /// <summary>
        /// The name of the certificate group, ofter referred to as group id.
        /// </summary>
        [JsonProperty(PropertyName = "id")]
        public string Id { get; set; }

        /// <summary>
        /// The certificate type as specified in the OPC UA spec 1.04.
        /// supported values:
        /// - RsaSha256ApplicationCertificateType (default)
        /// - ApplicationCertificateType
        /// </summary>
        [JsonProperty(PropertyName = "certificateType")]
        public string CertificateType { get; set; }

        /// <summary>
        /// The subject as distinguished name.
        /// </summary>
        [JsonProperty(PropertyName = "subjectName")]
        public string SubjectName { get; set; }

        /// <summary>
        /// The default certificate lifetime in months.
        /// Default: 24 months.
        /// </summary>
        [JsonProperty(PropertyName = "defaultCertificateLifetime")]
        public ushort DefaultCertificateLifetime { get; set; }

        /// <summary>
        /// The default certificate key size in bits.
        /// Allowed values: 2048, 3072, 4096
        /// </summary>
        [JsonProperty(PropertyName = "defaultCertificateKeySize")]
        public ushort DefaultCertificateKeySize { get; set; }

        /// <summary>
        /// The default certificate SHA-2 hash size in bits.
        /// Allowed values: 256 (default), 384, 512
        /// </summary>
        [JsonProperty(PropertyName = "defaultCertificateHashSize")]
        public ushort DefaultCertificateHashSize { get; set; }

        /// <summary>
        /// The default issuer CA certificate lifetime in months.
        /// Default: 60 months.
        /// </summary>
        [JsonProperty(PropertyName = "issuerCACertificateLifetime")]
        public ushort IssuerCACertificateLifetime { get; set; }

        /// <summary>
        /// The default issuer CA certificate key size in bits.
        /// Allowed values: 2048, 3072, 4096
        /// </summary>
        [JsonProperty(PropertyName = "issuerCACertificateKeySize")]
        public ushort IssuerCACertificateKeySize { get; set; }

        /// <summary>
        /// The default issuer CA certificate key size in bits.
        /// Allowed values: 2048, 3072, 4096
        /// </summary>
        [JsonProperty(PropertyName = "issuerCACertificateHashSize")]
        public ushort IssuerCACertificateHashSize { get; set; }

        /// <summary>
        /// The endpoint URL for the CRL Distributionpoint in the Issuer CA certificate.
        /// The names %servicehost%, %serial% and %group% are replaced with cert values.
        /// default: 'http://%servicehost%/certs/crl/%serial%/%group%.crl'
        /// </summary>
        [JsonProperty(PropertyName = "issuerCACRLDistributionPoint")]
        public string IssuerCACrlDistributionPoint { get; set; }

        /// <summary>
        /// The endpoint URL for the Issuer CA Authority Information Access.
        /// The names %servicehost%, %serial% and %group% are replaced with cert values.
        /// default: 'http://%servicehost%/certs/issuer/%serial%/%group%.cer'
        /// </summary>
        [JsonProperty(PropertyName = "issuerCAAuthorityInformationAccess")]
        public string IssuerCAAuthorityInformationAccess { get; set; }

        /// <summary>
        /// Convert to gds model
        /// </summary>
        /// <returns></returns>
        public Opc.Ua.Gds.Server.CertificateGroupConfiguration ToGdsServerModel() {
            return new Opc.Ua.Gds.Server.CertificateGroupConfiguration {
                Id = Id,
                CertificateType = CertificateType,
                SubjectName = SubjectName,
                BaseStorePath = "/" + Id.ToLower(),
                DefaultCertificateHashSize = DefaultCertificateHashSize,
                DefaultCertificateKeySize = DefaultCertificateKeySize,
                DefaultCertificateLifetime = DefaultCertificateLifetime,
                CACertificateHashSize = IssuerCACertificateHashSize,
                CACertificateKeySize = IssuerCACertificateKeySize,
                CACertificateLifetime = IssuerCACertificateLifetime
            };
        }
    }
}
