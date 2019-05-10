// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace Microsoft.Azure.IIoT.OpcUa.Vault.Services.KeyVault {
    using Microsoft.Azure.IIoT.OpcUa.Vault.Services.KeyVault.Models;
    using System;
    using System.Collections.Generic;
    using System.Security.Cryptography;
    using System.Security.Cryptography.X509Certificates;
    using System.Threading;
    using System.Threading.Tasks;
    using Microsoft.Azure.KeyVault.Models;
    using Opc.Ua;

    /// <summary>
    /// Key vault service client
    /// </summary>
    public interface IKeyVaultServiceClient {

        /// <summary>
        /// Read the OpcVault CertificateConfigurationGroups as Json.
        /// </summary>
        /// <param name="ct"></param>
        /// <returns></returns>
        Task<string> GetCertificateConfigurationGroupsAsync(
            CancellationToken ct = default);

        /// <summary>
        /// Write the OpcVault CertificateConfigurationGroups as Json.
        /// </summary>
        /// <param name="json"></param>
        /// <param name="ct"></param>
        /// <returns></returns>
        Task<string> PutCertificateConfigurationGroupsAsync(string json,
            CancellationToken ct = default);



        /// <summary>
        /// Get Certificate bundle from key Vault.
        /// </summary>
        /// <param name="groupId">Key Vault name</param>
        /// <param name="ct">CancellationToken</param>
        /// <returns></returns>
        Task<CertificateBundle> GetCertificateAsync(string groupId,
            CancellationToken ct = default);

        /// <summary>
        /// Read all certificate versions of a certificate.
        /// </summary>
        /// <param name="groupId"></param>
        /// <param name="thumbprint">filter for thumbprint</param>
        /// <param name="nextPageLink"></param>
        /// <param name="pageSize"></param>
        /// <param name="ct"></param>
        /// <returns></returns>
        Task<(X509Certificate2Collection, string)> ListCertificateVersionsAsync(
            string groupId, string thumbprint = null, string nextPageLink = null,
            int? pageSize = null, CancellationToken ct = default);

        /// <summary>
        /// Read all certificate versions of a certificate.
        /// </summary>
        /// <param name="groupId"></param>
        /// <param name="ct"></param>
        /// <returns></returns>
        Task<IList<CertificateKeyInfo>> ListCertificateVersionsKeyInfoAsync(
            string groupId, CancellationToken ct = default);

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

        /// <summary>
        /// Imports an existing CA certificate in specified group,
        /// and tags it for trusted or issuer store.
        /// </summary>
        /// <param name="groupId"></param>
        /// <param name="certificates"></param>
        /// <param name="trusted"></param>
        /// <param name="ct"></param>
        /// <returns></returns>
        Task ImportIssuerCACertificate(string groupId,
            X509Certificate2Collection certificates, bool trusted,
            CancellationToken ct = default);

        /// <summary>
        /// Creates a new CA certificate in specified group,
        /// and tags it for trusted or issuer store.
        /// </summary>
        /// <param name="groupId"></param>
        /// <param name="subject"></param>
        /// <param name="notBefore"></param>
        /// <param name="notAfter"></param>
        /// <param name="keySize"></param>
        /// <param name="hashSize"></param>
        /// <param name="trusted"></param>
        /// <param name="crlDistributionPoint"></param>
        /// <param name="ct"></param>
        /// <returns></returns>
        Task<X509Certificate2> CreateCACertificateAsync(string groupId,
            string subject, DateTime notBefore, DateTime notAfter,
            int keySize, int hashSize, bool trusted,
            string crlDistributionPoint, CancellationToken ct = default);

        /// <summary>
        /// Creates a new signed application certificate in specified group.
        /// </summary>
        /// <remarks>
        /// The key for the certificate is created in KeyVault, then exported.
        /// In order to delete the created key, the user principal needs
        /// create, get and delete rights for KeyVault certificates
        /// </remarks>
        /// <param name="groupId"></param>
        /// <param name="issuerCert"></param>
        /// <param name="applicationUri"></param>
        /// <param name="applicationName"></param>
        /// <param name="subjectName"></param>
        /// <param name="domainNames"></param>
        /// <param name="notBefore"></param>
        /// <param name="notAfter"></param>
        /// <param name="keySize"></param>
        /// <param name="hashSize"></param>
        /// <param name="generator"></param>
        /// <param name="authorityInformationAccess"></param>
        /// <param name="ct"></param>
        /// <returns></returns>
        Task<X509Certificate2> CreateSignedKeyPairCertAsync(
            string groupId, X509Certificate2 issuerCert, string applicationUri,
            string applicationName, string subjectName, string[] domainNames,
            DateTime notBefore, DateTime notAfter, int keySize, int hashSize,
            KeyVaultSignatureGenerator generator, string authorityInformationAccess,
            CancellationToken ct = default);

        /// <summary>
        /// Imports a CRL for group.
        /// </summary>
        /// <param name="groupId"></param>
        /// <param name="certificate"></param>
        /// <param name="crl"></param>
        /// <param name="ct"></param>
        /// <returns></returns>
        Task ImportIssuerCACrl(string groupId, X509Certificate2 certificate,
            X509CRL crl, CancellationToken ct = default);

        /// <summary>
        /// Load CRL for CA cert in group.
        /// </summary>
        /// <param name="groupId"></param>
        /// <param name="certificate"></param>
        /// <param name="ct"></param>
        /// <returns></returns>
        Task<X509CRL> LoadIssuerCACrl(string groupId, X509Certificate2 certificate,
            CancellationToken ct = default);

        /// <summary>
        /// Load CRL by ThumbPrint in group.
        /// </summary>
        /// <param name="groupId"></param>
        /// <param name="thumbPrint"></param>
        /// <param name="ct"></param>
        /// <returns></returns>
        Task<X509CRL> LoadIssuerCACrl(string groupId, string thumbPrint,
            CancellationToken ct = default);

        /// <summary>
        /// Imports a Private Key for specified group and certificate.
        /// </summary>
        /// <param name="groupId"></param>
        /// <param name="requestId"></param>
        /// <param name="privateKey"></param>
        /// <param name="privateKeyFormat"></param>
        /// <param name="ct"></param>
        /// <returns></returns>
        Task ImportKeySecretAsync(string groupId, string requestId, byte[] privateKey,
            string privateKeyFormat, CancellationToken ct = default);

        /// <summary>
        /// Load Private Key for certificate in group.
        /// </summary>
        /// <param name="groupId"></param>
        /// <param name="requestId"></param>
        /// <param name="privateKeyFormat"></param>
        /// <param name="ct"></param>
        /// <returns></returns>
        Task<byte[]> LoadKeySecretAsync(string groupId, string requestId,
            string privateKeyFormat, CancellationToken ct = default);

        /// <summary>
        /// Accept Private Key for certificate in group.
        /// </summary>
        /// <param name="groupId"></param>
        /// <param name="requestId"></param>
        /// <param name="ct"></param>
        /// <returns></returns>
        Task InvalidateKeySecretAsync(string groupId, string requestId,
            CancellationToken ct = default);

        /// <summary>
        /// Delete Private Key for certificate in group.
        /// </summary>
        /// <param name="groupId"></param>
        /// <param name="requestId"></param>
        /// <param name="ct"></param>
        /// <returns></returns>
        Task DeleteKeySecretAsync(string groupId, string requestId,
            CancellationToken ct = default);

        /// <summary>
        /// Creates a trust list with all certs and crls in issuer
        /// and trusted list.
        /// </summary>
        /// <param name="groupId"></param>
        /// <param name="maxResults"></param>
        /// <param name="nextPageLink"></param>
        /// <param name="ct"></param>
        /// <returns></returns>
        Task<KeyVaultTrustListModel> GetTrustListAsync(
            string groupId, int? maxResults, string nextPageLink,
            CancellationToken ct = default);

        /// <summary>
        /// Purge all CRL and Certificates groups.
        /// Use for unit test only!
        /// </summary>
        /// <param name="configId"></param>
        /// <param name="groupId"></param>
        /// <param name="ct"></param>
        /// <returns></returns>
        Task PurgeAsync(string configId = null, string groupId = null,
            CancellationToken ct = default);
    }
}