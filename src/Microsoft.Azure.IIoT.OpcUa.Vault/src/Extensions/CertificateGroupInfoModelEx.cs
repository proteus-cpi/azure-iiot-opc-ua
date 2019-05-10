// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------


namespace Microsoft.Azure.IIoT.OpcUa.Vault.Models {
    using Opc.Ua.Gds.Server;
    using Opc.Ua;
    using System;
    using System.Linq;

    /// <summary>
    /// Cert group configuration extensions
    /// </summary>
    public static class CertificateGroupInfoModelEx {

        /// <summary>
        /// Convert to gds model
        /// </summary>
        /// <returns></returns>
        public static CertificateGroupConfiguration ToGdsServerModel(
            this CertificateGroupInfoModel model) {
            return new CertificateGroupConfiguration {
                Id = model.Id,
                CertificateType = model.CertificateType.ToString(),
                SubjectName = model.SubjectName,
                BaseStorePath = "/" + model.Id.ToLower(),
                DefaultCertificateHashSize = model.DefaultCertificateHashSize,
                DefaultCertificateKeySize = model.DefaultCertificateKeySize,
                DefaultCertificateLifetime = model.DefaultCertificateLifetime,
                CACertificateHashSize = model.IssuerCACertificateHashSize,
                CACertificateKeySize = model.IssuerCACertificateKeySize,
                CACertificateLifetime = model.IssuerCACertificateLifetime
            };
        }

        /// <summary>
        /// Validate configuration
        /// </summary>
        /// <param name="model"></param>
        public static void ValidateConfiguration(this CertificateGroupInfoModel model) {
            var delimiters = new char[] { ' ', '\r', '\n' };
            var updateIdWords = model.Id.Split(delimiters,
                StringSplitOptions.RemoveEmptyEntries);

            if (updateIdWords.Length != 1) {
                throw new ArgumentException(
                    "Invalid number of words in group Id");
            }

            model.Id = updateIdWords[0];

            if (!model.Id.All(char.IsLetterOrDigit)) {
                throw new ArgumentException(
                    "Invalid characters in group Id");
            }

            // verify subject
            var subjectList = Utils.ParseDistinguishedName(model.SubjectName);
            if (subjectList == null ||
                subjectList.Count == 0) {
                throw new ArgumentException(
                    "Invalid Subject");
            }

            if (!subjectList.Any(c => c.StartsWith("CN=",
                StringComparison.InvariantCulture))) {
                throw new ArgumentException(
                    "Invalid Subject, must have a common name entry");
            }

            // enforce proper formatting for the subject name string
            model.SubjectName = string.Join(", ", subjectList);
            switch (model.CertificateType) {
                case CertificateType.ApplicationCertificateType:
                case CertificateType.RsaSha256ApplicationCertificateType:
                    break;
                case CertificateType.HttpsCertificateType:
                case CertificateType.RsaMinApplicationCertificateType:
                case CertificateType.UserCredentialCertificateType:
                    // only allow specific cert types for now
                    throw new NotSupportedException(
                        "Certificate type not supported");
                default:
                    throw new ArgumentException(
                        "Unknown and invalid CertificateType");
            }

            // specify ranges for lifetime (months)
            if (model.DefaultCertificateLifetime < 1 ||
                model.IssuerCACertificateLifetime < 1 ||
                model.DefaultCertificateLifetime * 2 >
                    model.IssuerCACertificateLifetime ||
                model.DefaultCertificateLifetime > 60 ||
                model.IssuerCACertificateLifetime > 1200) {
                throw new ArgumentException(
                    "Invalid lifetime");
            }

            if (model.DefaultCertificateKeySize < 2048 ||
                model.DefaultCertificateKeySize % 1024 != 0 ||
                model.DefaultCertificateKeySize > 2048) {
                throw new ArgumentException(
                    "Invalid key size, must be 2048, 3072 or 4096");
            }

            if (model.IssuerCACertificateKeySize < 2048 ||
                model.IssuerCACertificateKeySize % 1024 != 0 ||
                model.IssuerCACertificateKeySize > 4096) {
                throw new ArgumentException(
                    "Invalid key size, must be 2048, 3072 or 4096");
            }

            if (model.DefaultCertificateKeySize > model.IssuerCACertificateKeySize) {
                throw new ArgumentException(
                    "Invalid key size, Isser CA key must be >= application key");
            }

            if (model.DefaultCertificateHashSize < 256 ||
                model.DefaultCertificateHashSize % 128 != 0 ||
                model.DefaultCertificateHashSize > 512) {
                throw new ArgumentException(
                    "Invalid hash size, must be 256, 384 or 512");
            }

            if (model.IssuerCACertificateHashSize < 256 ||
                model.IssuerCACertificateHashSize % 128 != 0 ||
                model.IssuerCACertificateHashSize > 512) {
                throw new ArgumentException(
                    "Invalid hash size, must be 256, 384 or 512");
            }
        }

    }

}
