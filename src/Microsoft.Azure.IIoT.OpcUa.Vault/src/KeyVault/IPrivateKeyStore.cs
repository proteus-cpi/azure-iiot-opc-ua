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
        /// Imports a Private Key for specified group and certificate.
        /// </summary>
        /// <param name="groupId"></param>
        /// <param name="requestId"></param>
        /// <param name="privateKey"></param>
        /// <param name="privateKeyFormat"></param>
        /// <param name="ct"></param>
        /// <returns></returns>
        Task ImportKeyAsync(string groupId, string requestId, byte[] privateKey,
            PrivateKeyFormat privateKeyFormat, CancellationToken ct = default);

        /// <summary>
        /// Load Private Key for certificate in group.
        /// </summary>
        /// <param name="groupId"></param>
        /// <param name="requestId"></param>
        /// <param name="privateKeyFormat"></param>
        /// <param name="ct"></param>
        /// <returns></returns>
        Task<byte[]> GetKeyAsync(string groupId, string requestId,
            PrivateKeyFormat privateKeyFormat, CancellationToken ct = default);

        /// <summary>
        /// Accept Private Key for certificate in group.
        /// </summary>
        /// <param name="groupId"></param>
        /// <param name="requestId"></param>
        /// <param name="ct"></param>
        /// <returns></returns>
        Task DisableKeyAsync(string groupId, string requestId,
            CancellationToken ct = default);

        /// <summary>
        /// Delete Private Key for certificate in group.
        /// </summary>
        /// <param name="groupId"></param>
        /// <param name="requestId"></param>
        /// <param name="ct"></param>
        /// <returns></returns>
        Task DeleteKeyAsync(string groupId, string requestId,
            CancellationToken ct = default);
    }
}