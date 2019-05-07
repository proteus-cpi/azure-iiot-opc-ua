// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace System.Security.Cryptography.X509Certificates {
    using Microsoft.Azure.IIoT.OpcUa.Vault.Models;
    using Opc.Ua;
    using System.Linq;

    /// <summary>
    /// X509 cert extensions
    /// </summary>
    public static class X509Certificate2Ex {

        /// <summary>
        /// Get file name or return default
        /// </summary>
        /// <param name="cert"></param>
        /// <param name="defaultName"></param>
        /// <returns></returns>
        public static string GetFileNameOrDefault(this X509CertificateModel cert,
            string defaultName) {
            try {
                var dn = Utils.ParseDistinguishedName(cert.Subject);
                var prefix = dn
                    .FirstOrDefault(x => x.StartsWith("CN=",
                    StringComparison.OrdinalIgnoreCase)).Substring(3);
                return prefix + " [" + cert.Thumbprint + "]";
            }
            catch {
                return defaultName;
            }
        }

        /// <summary>
        /// Create certificate from cert
        /// </summary>
        /// <param name="certificate"></param>
        /// <param name="withCertificate"></param>
        public static X509CertificateModel ToServiceModel(this X509Certificate2 certificate,
            bool withCertificate = true) {
            return new X509CertificateModel {
                Certificate = withCertificate ? certificate.RawData : null,
                Thumbprint = certificate.Thumbprint,
                SerialNumber = certificate.SerialNumber,
                NotBefore = certificate.NotBefore,
                NotAfter = certificate.NotAfter,
                Subject = certificate.Subject
            };
        }

        /// <summary>
        /// Convert to framework model
        /// </summary>
        /// <returns></returns>
        public static X509Certificate2 ToStackModel(this X509CertificateModel model) {
            return new X509Certificate2(model.Certificate);
        }
    }
}
