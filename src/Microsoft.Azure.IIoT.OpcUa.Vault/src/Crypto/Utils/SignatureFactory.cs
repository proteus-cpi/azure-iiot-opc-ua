// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace Microsoft.Azure.IIoT.OpcUa.Vault.KeyVault {
    using Org.BouncyCastle.Asn1;
    using Org.BouncyCastle.Asn1.Pkcs;
    using Org.BouncyCastle.Asn1.X509;
    using Org.BouncyCastle.Crypto;
    using System.IO;
    using System;
    using System.Security.Cryptography;
    using System.Security.Cryptography.X509Certificates;

    /// <summary>
    /// The signature factory for Bouncy Castle to sign a digest with a KeyVault key.
    /// </summary>
    internal sealed class SignatureFactory : ISignatureFactory {

        /// <inheritdoc/>
        public object AlgorithmDetails => _algID;

        /// <summary>
        /// Constructor which also specifies a source of randomness to be
        /// used if one is required.
        /// </summary>
        /// <param name="hashAlgorithm">The name of the signature algorithm
        /// to use.</param>
        /// <param name="generator">The signature generator.</param>
        public SignatureFactory(HashAlgorithmName hashAlgorithm,
            X509SignatureGenerator generator) {
            _hashAlgorithm = hashAlgorithm;
            _generator = generator;
            _algID = new AlgorithmIdentifier(GetOid(hashAlgorithm));
        }

        /// <inheritdoc/>
        public IStreamCalculator CreateCalculator() {
            return new StreamCalculator(_generator, _hashAlgorithm);
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
            if (hashAlgorithm == HashAlgorithmName.SHA384) {
                return PkcsObjectIdentifiers.Sha384WithRsaEncryption;
            }
            if (hashAlgorithm == HashAlgorithmName.SHA512) {
                return PkcsObjectIdentifiers.Sha512WithRsaEncryption;
            }
            throw new ArgumentOutOfRangeException(nameof(hashAlgorithm));
        }

        /// <summary>
        /// Signs a Bouncy Castle digest stream with the .Net X509SignatureGenerator.
        /// </summary>
        private sealed class StreamCalculator : IStreamCalculator {

            /// <inheritdoc/>
            public Stream Stream { get; }

            /// <summary>
            /// Ctor for the stream calculator.
            /// </summary>
            /// <param name="generator">The X509SignatureGenerator to sign the digest.</param>
            /// <param name="hashAlgorithm">The hash algorithm to use for the signature.</param>
            public StreamCalculator(X509SignatureGenerator generator,
                HashAlgorithmName hashAlgorithm) {
                Stream = new MemoryStream();
                _generator = generator;
                _hashAlgorithm = hashAlgorithm;
            }

            /// <inheritdoc/>
            public object GetResult() {
                var memStream = Stream as MemoryStream;
                var digest = memStream.ToArray();
                var signature = _generator.SignData(digest, _hashAlgorithm);
                return new MemoryBlockResult(signature);
            }

            /// <summary>
            /// Helper for Bouncy Castle signing operation to store the result in
            /// a memory block.
            /// </summary>
            public class MemoryBlockResult : IBlockResult {

                /// <inheritdoc/>
                public MemoryBlockResult(byte[] data) {
                    _data = data;
                }

                /// <inheritdoc/>
                public byte[] Collect() {
                    return _data;
                }

                /// <inheritdoc/>
                public int Collect(byte[] destination, int offset) {
                    throw new NotImplementedException();
                }

                private readonly byte[] _data;
            }

            private readonly X509SignatureGenerator _generator;
            private readonly HashAlgorithmName _hashAlgorithm;
        }

        private readonly AlgorithmIdentifier _algID;
        private readonly HashAlgorithmName _hashAlgorithm;
        private readonly X509SignatureGenerator _generator;
    }
}
