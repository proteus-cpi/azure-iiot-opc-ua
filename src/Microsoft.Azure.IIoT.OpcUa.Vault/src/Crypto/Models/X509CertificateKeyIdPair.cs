// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace Microsoft.Azure.IIoT.OpcUa.Vault.KeyVault.Models {
    using System.Security.Cryptography.X509Certificates;

    /// <summary>
    /// A Certificate and private key handle
    /// </summary>
    public class X509CertificateKeyIdPair {

        /// <summary>
        /// Certificate
        /// </summary>
        public X509Certificate2 Certificate { get; set; }

        /// <summary>
        /// Private key identifier to look up the private key
        /// </summary>
        public string KeyIdentifier { get; set; }

        /// <summary>
        /// Attributes
        /// </summary>
        public string SecretIdentifier { get; set; }
    }
}

