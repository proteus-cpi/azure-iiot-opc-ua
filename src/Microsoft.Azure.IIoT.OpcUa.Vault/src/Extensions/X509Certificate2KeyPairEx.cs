// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace System.Security.Cryptography.X509Certificates {
    using Opc.Ua.Gds.Server;
    using Microsoft.Azure.IIoT.OpcUa.Vault.Models;

    /// <summary>
    /// Private key pair extensions
    /// </summary>
    public static class X509Certificate2KeyPairEx {

        /// <summary>
        /// Create private key pair
        /// </summary>
        /// <param name="pair"></param>
        public static X509CertificatePrivateKeyPairModel ToServiceModel(
            this X509Certificate2KeyPair pair) {
            return new X509CertificatePrivateKeyPairModel {
                Certificate = pair.Certificate.ToServiceModel(),
                PrivateKey = pair.PrivateKey,
                PrivateKeyFormat = pair.PrivateKeyFormat
            };
        }

        /// <summary>
        /// Create private key pair
        /// </summary>
        /// <param name="pair"></param>
        public static X509Certificate2KeyPair ToStackModel(
            this X509CertificatePrivateKeyPairModel pair) {
            return new X509Certificate2KeyPair(pair.Certificate.ToStackModel(),
                pair.PrivateKeyFormat, pair.PrivateKey);
        }
    }
}
