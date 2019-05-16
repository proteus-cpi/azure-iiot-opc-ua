// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace Microsoft.Azure.IIoT.OpcUa.Vault.KeyVault {
    using Microsoft.Azure.IIoT.OpcUa.Vault.KeyVault.Models;
    using Microsoft.Azure.KeyVault.Models;
    using System.Security.Cryptography.X509Certificates;

    /// <summary>
    /// Trust list model extensions
    /// </summary>
    public static class X509CertificateKeyIdPairEx {

        /// <summary>
        /// Convert to stack model
        /// </summary>
        /// <param name="certBundle"></param>
        /// <returns></returns>
        public static X509CertificateKeyIdPair ToStackModel(
            this CertificateBundle certBundle) {
            return new X509CertificateKeyIdPair {
                Certificate = new X509Certificate2(certBundle.Cer),
                SecretIdentifier = certBundle.SecretIdentifier.Identifier,
                KeyIdentifier = certBundle.KeyIdentifier.Identifier
            };
        }
    }
}
