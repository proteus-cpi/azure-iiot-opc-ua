// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace Microsoft.Azure.IIoT.OpcUa.Vault.KeyVault {
    using System;
    using System.Security.Cryptography;
    using System.Security.Cryptography.X509Certificates;

    /// <summary>
    /// The signature factory for Bouncy Castle to sign a digest with a KeyVault key.
    /// </summary>
    public class KeyVaultSignatureFactory : Org.BouncyCastle.Crypto.ISignatureFactory {
        private readonly Org.BouncyCastle.Asn1.X509.AlgorithmIdentifier _algID;
        private readonly HashAlgorithmName _hashAlgorithm;
        private readonly X509SignatureGenerator _generator;

        /// <summary>
        /// Constructor which also specifies a source of randomness to be used if one is required.
        /// </summary>
        /// <param name="hashAlgorithm">The name of the signature algorithm to use.</param>
        /// <param name="generator">The signature generator.</param>
        public KeyVaultSignatureFactory(HashAlgorithmName hashAlgorithm, X509SignatureGenerator generator) {
            Org.BouncyCastle.Asn1.DerObjectIdentifier sigOid;
            if (hashAlgorithm == HashAlgorithmName.SHA256) {
                sigOid = Org.BouncyCastle.Asn1.Pkcs.PkcsObjectIdentifiers.Sha256WithRsaEncryption;
            }
            else if (hashAlgorithm == HashAlgorithmName.SHA384) {
                sigOid = Org.BouncyCastle.Asn1.Pkcs.PkcsObjectIdentifiers.Sha384WithRsaEncryption;
            }
            else if (hashAlgorithm == HashAlgorithmName.SHA512) {
                sigOid = Org.BouncyCastle.Asn1.Pkcs.PkcsObjectIdentifiers.Sha512WithRsaEncryption;
            }
            else {
                throw new ArgumentOutOfRangeException(nameof(hashAlgorithm));
            }
            _hashAlgorithm = hashAlgorithm;
            _generator = generator;
            _algID = new Org.BouncyCastle.Asn1.X509.AlgorithmIdentifier(sigOid);
        }

        /// <inheritdoc/>
        public object AlgorithmDetails => _algID;

        /// <inheritdoc/>
        public Org.BouncyCastle.Crypto.IStreamCalculator CreateCalculator() {
            return new KeyVaultStreamCalculator(_generator, _hashAlgorithm);
        }
    }
}
