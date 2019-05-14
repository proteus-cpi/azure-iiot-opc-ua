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
        /// Validate configuration
        /// </summary>
        /// <param name="model"></param>
        public static void Validate(this CertificateGroupInfoModel model) {
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

        /// <summary>
        /// Patch document
        /// </summary>
        /// <param name="document"></param>
        /// <param name="request"></param>
        public static void Patch(this CertificateGroupInfoModel document,
            CertificateGroupUpdateModel request) {
            if (!string.IsNullOrEmpty(request.SubjectName)) {
                document.SubjectName = request.SubjectName;
            }
            if (request.CertificateType != null) {
                document.CertificateType = request.CertificateType.Value;
            }
            if (request.DefaultCertificateLifetime != null) {
                document.DefaultCertificateLifetime = request.DefaultCertificateLifetime.Value;
            }
            if (request.DefaultCertificateKeySize != null) {
                document.DefaultCertificateKeySize = request.DefaultCertificateKeySize.Value;
            }
            if (request.DefaultCertificateHashSize != null) {
                document.DefaultCertificateHashSize = request.DefaultCertificateHashSize.Value;
            }
            if (request.IssuerCACertificateLifetime != null) {
                document.IssuerCACertificateLifetime = request.IssuerCACertificateLifetime.Value;
            }
            if (request.IssuerCACertificateKeySize != null) {
                document.IssuerCACertificateKeySize = request.IssuerCACertificateKeySize.Value;
            }
            if (request.IssuerCACertificateHashSize != null) {
                document.IssuerCACertificateHashSize = request.IssuerCACertificateHashSize.Value;
            }
            document.Validate();
        }

        /// <summary>
        /// Return subject name
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        public static string GetSubjectName(this CertificateGroupInfoModel model) {
            return model.SubjectName?.Replace("localhost", Utils.GetHostName()) ??
                kDefaultSubject;
        }

        /// <summary>
        /// Build crl distribution point url
        /// </summary>
        /// <param name="model"></param>
        /// <param name="serviceHost"></param>
        /// <returns></returns>
        public static string GetCrlDistributionPointUrl(this CertificateGroupInfoModel model,
            string serviceHost) {
            if (!string.IsNullOrWhiteSpace(model.IssuerCACrlDistributionPoint)) {
                return PatchEndpointUrl(model, serviceHost, model.IssuerCACrlDistributionPoint);
            }
            return null;
        }

        /// <summary>
        /// Build auth url
        /// </summary>
        /// <param name="model"></param>
        /// <param name="serviceHost"></param>
        /// <returns></returns>
        public static string GetAuthorityInformationAccessUrl(this CertificateGroupInfoModel model,
            string serviceHost) {
            if (!string.IsNullOrWhiteSpace(model.IssuerCAAuthorityInformationAccess)) {
                return PatchEndpointUrl(model, serviceHost, model.IssuerCAAuthorityInformationAccess);
            }
            return null;
        }

        /// <summary>
        /// Patch endpoint url
        /// </summary>
        /// <param name="endPointUrl"></param>
        /// <param name="model"></param>
        /// <param name="serviceHost"></param>
        /// <returns></returns>
        private static string PatchEndpointUrl(CertificateGroupInfoModel model, 
            string serviceHost, string endPointUrl) {
            var patchedServiceHost = endPointUrl.Replace("%servicehost%", serviceHost);
            return patchedServiceHost.Replace("%group%", model.Id.ToLower());
        }

        /// <summary>
        /// Create default configuration
        /// </summary>
        /// <param name="request"></param>
        /// <returns></returns>
        public static CertificateGroupInfoModel GetDefaultGroupConfiguration(
            CertificateGroupCreateRequestModel request) {
            var config = new CertificateGroupInfoModel {
                Id = Guid.NewGuid().ToString(),
                Name = request.Name ?? "Default",
                SubjectName = request.SubjectName ?? kDefaultSubject,
                CertificateType = request.CertificateType,
                DefaultCertificateLifetime = 24,
                DefaultCertificateHashSize = 256,
                DefaultCertificateKeySize = 2048,
                IssuerCACertificateLifetime = 60,
                IssuerCACertificateHashSize = 256,
                IssuerCACertificateKeySize = 2048,
                IssuerCACrlDistributionPoint = "http://%servicehost%/certs/crl/%serial%/%group%.crl",
                IssuerCAAuthorityInformationAccess = "http://%servicehost%/certs/issuer/%serial%/%group%.cer"
            };
            config.Validate();
            return config;
        }

        private const string kDefaultSubject = "CN=Azure Industrial IoT CA, O=Microsoft Corp.";
    }
}
