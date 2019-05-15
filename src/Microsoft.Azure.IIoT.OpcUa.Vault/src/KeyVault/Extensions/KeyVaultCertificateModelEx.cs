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
    public static class KeyVaultCertificateModelEx {

        /// <summary>
        /// Convert to stack model
        /// </summary>
        /// <param name="certBundle"></param>
        /// <returns></returns>
        public static KeyVaultCertificateModel ToStackModel(
            this CertificateBundle certBundle) {
            return new KeyVaultCertificateModel {
                Certificate = new X509Certificate2(certBundle.Cer),
                CertIdentifier = certBundle.CertificateIdentifier.Identifier,
                SecretIdentifier = certBundle.SecretIdentifier.Identifier,
                KeyIdentifier = certBundle.KeyIdentifier.Identifier
            };
        }
    }
}
