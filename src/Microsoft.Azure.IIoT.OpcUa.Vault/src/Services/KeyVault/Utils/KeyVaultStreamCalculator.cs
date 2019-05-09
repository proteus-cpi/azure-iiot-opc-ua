// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace Microsoft.Azure.IIoT.OpcUa.Vault.KeyVault {
    using System.IO;
    using System.Security.Cryptography;
    using System.Security.Cryptography.X509Certificates;

    /// <summary>
    /// Signs a Bouncy Castle digest stream with the .Net X509SignatureGenerator.
    /// </summary>
    public class KeyVaultStreamCalculator : Org.BouncyCastle.Crypto.IStreamCalculator {

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

        private readonly X509SignatureGenerator _generator;
        private readonly HashAlgorithmName _hashAlgorithm;
    }
}
