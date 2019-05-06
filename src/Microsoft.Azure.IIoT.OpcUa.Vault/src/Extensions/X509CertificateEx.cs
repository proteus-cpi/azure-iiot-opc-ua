// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace System.Security.Cryptography.X509Certificates {
    using Opc.Ua;
    using System.Linq;

    /// <summary>
    /// X509 cert extensions
    /// </summary>
    public static class X509CertificateEx {

        /// <summary>
        /// Get file name or return default
        /// </summary>
        /// <param name="cert"></param>
        /// <param name="defaultName"></param>
        /// <returns></returns>
        public static string GetFileNameOrDefault(this X509Certificate2 cert,
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
    }
}
