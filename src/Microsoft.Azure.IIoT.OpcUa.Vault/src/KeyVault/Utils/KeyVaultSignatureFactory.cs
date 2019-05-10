// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace Microsoft.Azure.IIoT.OpcUa.Vault.KeyVault {
    using Org.BouncyCastle.Asn1;
    using Org.BouncyCastle.Asn1.Pkcs;
    using Org.BouncyCastle.Asn1.X509;
    using Org.BouncyCastle.Crypto;
    using System;
    using System.Security.Cryptography;
    using System.Security.Cryptography.X509Certificates;

    /// <summary>
    /// The signature factory for Bouncy Castle to sign a digest with a KeyVault key.
    /// </summary>
    public class KeyVaultSignatureFactory : ISignatureFactory {

        /// <inheritdoc/>
        public object AlgorithmDetails => _algID;

        /// <summary>
        /// Constructor which also specifies a source of randomness to be
        /// used if one is required.
        /// </summary>
        /// <param name="hashAlgorithm">The name of the signature algorithm
        /// to use.</param>
        /// <param name="generator">The signature generator.</param>
        public KeyVaultSignatureFactory(HashAlgorithmName hashAlgorithm,
            X509SignatureGenerator generator) {
            _hashAlgorithm = hashAlgorithm;
            _generator = generator;
            _algID = new AlgorithmIdentifier(GetOid(hashAlgorithm));
        }

        /// <inheritdoc/>
        public IStreamCalculator CreateCalculator() {
            return new KeyVaultStreamCalculator(_generator, _hashAlgorithm);
        }

        /// <summary>
        /// Get oid for algorithm
        /// </summary>
        /// <param name="hashAlgorithm"></param>
        /// <returns></returns>
        private static DerObjectIdentifier GetOid(HashAlgorithmName hashAlgorithm) {
            if (hashAlgorithm == HashAlgorithmName.SHA256) {
                return PkcsObjectIdentifiers.Sha256WithRsaEncryption;
            }
            else if (hashAlgorithm == HashAlgorithmName.SHA384) {
                return PkcsObjectIdentifiers.Sha384WithRsaEncryption;
            }
            else if (hashAlgorithm == HashAlgorithmName.SHA512) {
                return PkcsObjectIdentifiers.Sha512WithRsaEncryption;
            }
            else {
                throw new ArgumentOutOfRangeException(nameof(hashAlgorithm));
            }
        }

        private readonly AlgorithmIdentifier _algID;
        private readonly HashAlgorithmName _hashAlgorithm;
        private readonly X509SignatureGenerator _generator;
    }
}
