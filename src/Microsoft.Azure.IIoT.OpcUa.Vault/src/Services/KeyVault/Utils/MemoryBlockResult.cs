// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace Microsoft.Azure.IIoT.OpcUa.Vault.KeyVault {
    using System;

    /// <summary>
    /// Helper for Bouncy Castle signing operation to store the result in
    /// a memory block.
    /// </summary>
    public class MemoryBlockResult : Org.BouncyCastle.Crypto.IBlockResult {

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
}
