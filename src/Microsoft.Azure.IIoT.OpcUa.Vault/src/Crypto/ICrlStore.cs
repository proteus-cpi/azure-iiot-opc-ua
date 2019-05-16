// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace Microsoft.Azure.IIoT.OpcUa.Vault.KeyVault {
    using System.Security.Cryptography.X509Certificates;
    using System.Threading;
    using System.Threading.Tasks;

    /// <summary>
    /// Crl store
    /// </summary>
    public interface ICrlStore {

        /// <summary>
        /// Imports a CRL for certificate.
        /// </summary>
        /// <param name="certificateName"></param>
        /// <param name="thumbPrint"></param>
        /// <param name="crl"></param>
        /// <param name="ct"></param>
        /// <returns></returns>
        Task ImportCrlAsync(string certificateName, string thumbPrint,
            X509Crl2 crl, CancellationToken ct = default);

        /// <summary>
        /// Load CRL for CA cert in group.
        /// </summary>
        /// <param name="certificateName"></param>
        /// <param name="thumbPrint"></param>
        /// <param name="ct"></param>
        /// <returns></returns>
        Task<X509Crl2> GetCrlAsync(string certificateName, string thumbPrint,
            CancellationToken ct = default);
    }
}