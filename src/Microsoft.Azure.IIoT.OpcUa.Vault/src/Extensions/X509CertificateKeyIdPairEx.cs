// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace System.Security.Cryptography.X509Certificates {
    using Microsoft.Azure.IIoT.Crypto;
    using Microsoft.Azure.IIoT.Crypto.Models;
    using System;
    using System.Threading;
    using System.Threading.Tasks;

    /// <summary>
    /// Private key pair extensions
    /// </summary>
    public static class X509CertificateKeyIdPairEx {

        /// <summary>
        /// Get private key certificate
        /// </summary>
        /// <param name="store"></param>
        /// <param name="pair"></param>
        /// <param name="ct"></param>
        public static async Task<X509Certificate2> GetPrivateKeyCertificateAsync(
            this IPrivateKeyStore store, X509CertificateKeyIdPair pair, 
            CancellationToken ct = default) {
            if (pair.Certificate.HasPrivateKey) {
                return pair.Certificate; // Already has one
            }
            var encoding = await store.GetEncodingAsync(pair.KeyIdentifier, ct);
            var privateKey = await store.GetKeyAsync(pair.KeyIdentifier, encoding, ct);
            if (encoding == PrivateKeyEncoding.PFX) {
              //  pair.Certificate.CreateCertificateWithPrivateKey(RSA.Create(privateKey));
            }
            else if (encoding == PrivateKeyEncoding.PEM) {
                return CertificateFactory.CreateCertificateWithPEMPrivateKey(
                    pair.Certificate, privateKey, string.Empty);
            }
            throw new NotSupportedException("Private key encoding not supported");
        }
    }
}
