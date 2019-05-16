// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace Microsoft.Azure.IIoT.OpcUa.Vault.KeyVault {
    using Microsoft.Azure.IIoT.OpcUa.Vault.KeyVault.Models;
    using System.Collections.Generic;
    using System.Security.Cryptography.X509Certificates;
    using System.Threading;
    using System.Threading.Tasks;

    /// <summary>
    /// Certificate storage
    /// </summary>
    public interface ICertificateStore {

        /// <summary>
        /// Imports an existing certificate and tags it for trusted or 
        /// issuer store.
        /// </summary>
        /// <param name="certificateName"></param>
        /// <param name="certificates"></param>
        /// <param name="trusted"></param>
        /// <param name="ct"></param>
        /// <returns></returns>
        Task ImportCertificateAsync(string certificateName,
            X509Certificate2Collection certificates, bool trusted,
            CancellationToken ct = default);

        /// <summary>
        /// Read all certificate versions of a certificate.
        /// </summary>
        /// <param name="certificateName"></param>
        /// <param name="thumbprint">filter for thumbprint</param>
        /// <param name="nextPageLink"></param>
        /// <param name="pageSize"></param>
        /// <param name="ct"></param>
        /// <returns></returns>
        Task<(X509Certificate2Collection, string)> QueryCertificatesAsync(
            string certificateName, string thumbprint = null, string nextPageLink = null,
            int? pageSize = null, CancellationToken ct = default);

        /// <summary>
        /// Read all certificate versions of a certificate.
        /// </summary>
        /// <param name="certificateName"></param>
        /// <param name="ct"></param>
        /// <returns></returns>
        Task<IList<X509CertificateKeyIdPair>> ListCertificatesAsync(
            string certificateName, CancellationToken ct = default);

        /// <summary>
        /// Get Certificate from certificate store
        /// </summary>
        /// <param name="certificateName">Key Vault name</param>
        /// <param name="ct">CancellationToken</param>
        /// <returns></returns>
        Task<X509CertificateKeyIdPair> GetCertificateAsync(string certificateName,
            CancellationToken ct = default);
    }
}