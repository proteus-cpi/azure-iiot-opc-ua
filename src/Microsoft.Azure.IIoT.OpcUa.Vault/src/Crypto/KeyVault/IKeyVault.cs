// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace Microsoft.Azure.IIoT.OpcUa.Vault.KeyVault {
    using Microsoft.Azure.IIoT.OpcUa.Vault.KeyVault.Models;
    using Microsoft.Azure.IIoT.Storage;
    using System.Threading;
    using System.Threading.Tasks;

    /// <summary>
    /// Key vault abstraction
    /// </summary>
    public interface IKeyVault : IKeyValueStore, IDigestSigner, ICertificateStore, ICertificateFactory {

        /// <summary>
        /// Retrieves a trust list with all certs and crls in issuer
        /// and trusted list.
        /// </summary>
        /// <param name="trustListId"></param>
        /// <param name="maxResults"></param>
        /// <param name="nextPageLink"></param>
        /// <param name="ct"></param>
        /// <returns></returns>
        Task<KeyVaultTrustListModel> GetTrustListAsync(
            string trustListId, int? maxResults, string nextPageLink,
            CancellationToken ct = default);
    }
}