// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace Microsoft.Azure.IIoT.OpcUa.Vault.KeyVault {
    using System;
    using System.Security.Cryptography;
    using Org.BouncyCastle.Crypto.Prng;

    /// <summary>
    /// Secure .Net Core Random Number generator wrapper for Bounce Castle.
    /// Creates an instance of RNGCryptoServiceProvider or an OpenSSL based version on other OS.
    /// </summary>
    internal class RandomGeneratorAdapter : IRandomGenerator, IDisposable {

        /// <summary>
        /// Create
        /// </summary>
        public RandomGeneratorAdapter() {
            _prg = RandomNumberGenerator.Create();
        }

        /// <inheritdoc/>
        public void Dispose() => _prg.Dispose();

        /// <inheritdoc/>
        public void AddSeedMaterial(byte[] seed) { }

        /// <summary>Add more seed material to the generator. Not needed here.</summary>
        public void AddSeedMaterial(long seed) { }

        /// <inheritdoc/>
        public void NextBytes(byte[] bytes) {
            _prg.GetBytes(bytes);
        }

        /// <inheritdoc/>
        public void NextBytes(byte[] bytes, int start, int len) {
            byte[] temp = new byte[len];
            _prg.GetBytes(temp);
            Array.Copy(temp, 0, bytes, start, len);
        }

        private readonly RandomNumberGenerator _prg;
    }
}
