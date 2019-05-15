﻿// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace Microsoft.Azure.IIoT.OpcUa.Vault.KeyVault {
    using Microsoft.Azure.IIoT.OpcUa.Vault.KeyVault.Models;
    using Microsoft.Azure.IIoT.Storage;
    using System;
    using System.Collections.Generic;
    using System.Security.Cryptography.X509Certificates;
    using System.Threading;
    using System.Threading.Tasks;

    /// <summary>
    /// Key vault abstraction
    /// </summary>
    public interface IKeyVault : IKeyValueStore, IDigestSigner, 
        ICrlStore, ITrustListStore {

        /// <summary>
        /// Creates a new signed application certificate in specified group.
        /// </summary>
        /// <remarks>
        /// The key for the certificate is created in KeyVault, then exported.
        /// In order to delete the created key, the user principal needs
        /// create, get and delete rights for KeyVault certificates
        /// </remarks>
        /// <param name="caCertId"></param>
        /// <param name="issuerCert"></param>
        /// <param name="applicationUri"></param>
        /// <param name="applicationName"></param>
        /// <param name="subjectName"></param>
        /// <param name="domainNames"></param>
        /// <param name="notBefore"></param>
        /// <param name="notAfter"></param>
        /// <param name="keySize"></param>
        /// <param name="hashSize"></param>
        /// <param name="signingKeyId"></param>
        /// <param name="authorityInformationAccess"></param>
        /// <param name="ct"></param>
        /// <returns></returns>
        Task<X509Certificate2> CreateSignedKeyPairCertAsync(
            string caCertId, X509Certificate2 issuerCert, string applicationUri,
            string applicationName, string subjectName, string[] domainNames,
            DateTime notBefore, DateTime notAfter, int keySize, int hashSize,
            string signingKeyId, string authorityInformationAccess,
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
        Task<(X509Certificate2Collection, string)> ListCertificatesAsync(
            string certificateName, string thumbprint = null, string nextPageLink = null,
            int? pageSize = null, CancellationToken ct = default);

        /// <summary>
        /// Read all certificate versions of a certificate.
        /// </summary>
        /// <param name="certificateName"></param>
        /// <param name="ct"></param>
        /// <returns></returns>
        Task<IList<KeyVaultCertificateModel>> GetCertificateVersionsAsync(
            string certificateName, CancellationToken ct = default);

        /// <summary>
        /// Get Certificate from key Vault.
        /// </summary>
        /// <param name="certificateName">Key Vault name</param>
        /// <param name="ct">CancellationToken</param>
        /// <returns></returns>
        Task<KeyVaultCertificateModel> GetCertificateAsync(string certificateName,
            CancellationToken ct = default);

        /// <summary>
        /// Imports an existing CA certificate in specified group,
        /// and tags it for trusted or issuer store.
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
        /// Creates a new CA certificate with specified name
        /// and tags it for trusted or issuer store.
        /// </summary>
        /// <param name="certificateName"></param>
        /// <param name="subject"></param>
        /// <param name="notBefore"></param>
        /// <param name="notAfter"></param>
        /// <param name="keySize"></param>
        /// <param name="hashSize"></param>
        /// <param name="trusted"></param>
        /// <param name="crlDistributionPoint"></param>
        /// <param name="ct"></param>
        /// <returns></returns>
        Task<X509Certificate2> CreateCertificateAsync(string certificateName,
            string subject, DateTime notBefore, DateTime notAfter,
            int keySize, int hashSize, bool trusted,
            string crlDistributionPoint, CancellationToken ct = default);
    }
}