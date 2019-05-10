// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace Microsoft.Azure.IIoT.OpcUa.Vault.KeyVault {
    using Org.BouncyCastle.Crypto;
    using System;
    using System.IO;
    using System.Security.Cryptography;
    using System.Security.Cryptography.X509Certificates;

    /// <summary>
    /// Signs a Bouncy Castle digest stream with the .Net X509SignatureGenerator.
    /// </summary>
    public class KeyVaultStreamCalculator : IStreamCalculator {

        /// <inheritdoc/>
        public Stream Stream { get; }

        /// <summary>
        /// Ctor for the stream calculator.
        /// </summary>
        /// <param name="generator">The X509SignatureGenerator to sign the digest.</param>
        /// <param name="hashAlgorithm">The hash algorithm to use for the signature.</param>
        public KeyVaultStreamCalculator(X509SignatureGenerator generator,
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
}
