// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace Microsoft.Azure.IIoT.OpcUa.Vault.Services.KeyVault.Models {
    using System.Security.Cryptography.X509Certificates;

    /// <summary>
    /// Certificate key info
    /// </summary>
    public struct CertificateKeyInfo {

        /// <summary>
        /// Certificate
        /// </summary>
        public X509Certificate2 Certificate { get; set; }

        /// <summary>
        /// Key
        /// </summary>
        public string KeyIdentifier { get; set; }
    }
}

