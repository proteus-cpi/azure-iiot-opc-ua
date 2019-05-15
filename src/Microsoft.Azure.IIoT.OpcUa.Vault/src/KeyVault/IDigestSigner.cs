// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace Microsoft.Azure.IIoT.OpcUa.Vault.KeyVault {
    using System.Security.Cryptography;
    using System.Threading;
    using System.Threading.Tasks;

    /// <summary>
    /// Signs digest
    /// </summary>
    public interface IDigestSigner {

        /// <summary>
        /// Sign a digest with the signing key.
        /// </summary>
        /// <param name="signingKey"></param>
        /// <param name="digest"></param>
        /// <param name="hashAlgorithm"></param>
        /// <param name="padding"></param>
        /// <param name="ct"></param>
        /// <returns></returns>
        Task<byte[]> SignDigestAsync(string signingKey, byte[] digest,
            HashAlgorithmName hashAlgorithm, RSASignaturePadding padding,
            CancellationToken ct = default);
    }
}