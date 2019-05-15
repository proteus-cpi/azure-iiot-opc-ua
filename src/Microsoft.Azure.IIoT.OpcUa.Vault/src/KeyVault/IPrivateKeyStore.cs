// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace Microsoft.Azure.IIoT.OpcUa.Vault.KeyVault {
    using Microsoft.Azure.IIoT.OpcUa.Vault.Models;
    using System.Threading;
    using System.Threading.Tasks;

    /// <summary>
    /// Manages private keys
    /// </summary>
    public interface IPrivateKeyStore {

        /// <summary>
        /// Imports a Private Key under specified keyId
        /// </summary>
        /// <param name="keyId"></param>
        /// <param name="privateKey"></param>
        /// <param name="privateKeyFormat"></param>
        /// <param name="ct"></param>
        /// <returns></returns>
        Task ImportKeyAsync(string keyId, byte[] privateKey,
            PrivateKeyFormat privateKeyFormat, 
            CancellationToken ct = default);

        /// <summary>
        /// Load Private Key Id
        /// </summary>
        /// <param name="keyId"></param>
        /// <param name="privateKeyFormat"></param>
        /// <param name="ct"></param>
        /// <returns></returns>
        Task<byte[]> GetKeyAsync(string keyId,
            PrivateKeyFormat privateKeyFormat, 
            CancellationToken ct = default);

        /// <summary>
        /// Accept Private Key with key Id
        /// </summary>
        /// <param name="keyId"></param>
        /// <param name="ct"></param>
        /// <returns></returns>
        Task DisableKeyAsync(string keyId,
            CancellationToken ct = default);

        /// <summary>
        /// Delete Private Key with key Id
        /// </summary>
        /// <param name="keyId"></param>
        /// <param name="ct"></param>
        /// <returns></returns>
        Task DeleteKeyAsync(string keyId,
            CancellationToken ct = default);
    }
}