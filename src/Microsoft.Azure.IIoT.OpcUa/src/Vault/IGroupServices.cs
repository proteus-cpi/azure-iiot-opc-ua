// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace Microsoft.Azure.IIoT.OpcUa.Vault {
    using Microsoft.Azure.IIoT.OpcUa.Vault.Models;
    using System.Threading.Tasks;

    /// <summary>
    /// Certificate group services
    /// </summary>
    public interface IGroupServices {

        /// <summary>
        /// Get all Issuer certificate versions in a pageable call.
        /// </summary>
        /// <param name="groupId">The group Id</param>
        /// <param name="withCertificates">true to return the
        /// base64 encoded certificates</param>
        /// <param name="nextPageLink">The next page</param>
        /// <param name="pageSize">max number of versions per call
        /// </param>
        /// <returns></returns>
        Task<X509CertificateCollectionModel> ListIssuerCACertificateVersionsAsync(
            string groupId, bool? withCertificates, string nextPageLink = null,
            int? pageSize = null);

        /// <summary>
        /// Get all certificates in the chain of the Issuer CA.
        /// </summary>
        /// <param name="groupId">The group groupId</param>
        /// <param name="thumbPrint">null for the latest Issuer CA
        /// cert, thumbprint to get a specific older version</param>
        /// <param name="nextPageLink">The next page</param>
        /// <param name="pageSize">max number of certificates per call
        /// </param>
        /// <returns></returns>
        Task<X509CertificateCollectionModel> GetIssuerCACertificateChainAsync(
            string groupId, string thumbPrint = null, string nextPageLink = null,
            int? pageSize = null);

        /// <summary>
        /// Get the CRLs for all certificates in the Issuer CA chain.
        /// </summary>
        /// <param name="groupId">The group groupId</param>
        /// <param name="thumbPrint">null for the latest Issuer CA cert,
        /// thumbprint to get a specific older version</param>
        /// <param name="nextPageLink">The next page</param>
        /// <param name="pageSize">max number of CRL per call</param>
        /// <returns></returns>
        Task<X509CrlCollectionModel> GetIssuerCACrlChainAsync(string groupId,
            string thumbPrint = null, string nextPageLink = null, int? pageSize = null);

        /// <summary>
        /// Get the default trustlist of a certificate group.
        /// Pageable.
        /// A trustlist contains an Issuer list and a Trusted list.
        /// Issuer and Trusted list each contain a list of certificates
        /// and CRLs.
        /// </summary>
        /// <param name="groupId"></param>
        /// <param name="nextPageLink"></param>
        /// <param name="pageSize"></param>
        /// <returns>The trust list page</returns>
        Task<TrustListModel> GetTrustListAsync(string groupId,
            string nextPageLink = null, int? pageSize = null);

        /// <summary>
        /// Create a new certificate request with a CSR.
        /// </summary>
        /// <param name="groupId">The group groupId</param>
        /// <param name="applicationUri">The application Uri</param>
        /// <param name="certificateRequest">The binary CSR</param>
        /// <returns></returns>
        Task<X509CertificateModel> ProcessSigningRequestAsync(
            string groupId, string applicationUri, byte[] certificateRequest);

        /// <summary>
        /// Create a new Issuer CA signed certificate and private key.
        /// </summary>
        /// <param name="groupId">The group Id</param>
        /// <param name="requestId">The request Id</param>
        /// <param name="applicationUri">The application Uri for the
        /// certificate</param>
        /// <param name="subjectName">The subject for the certificate
        /// </param>
        /// <param name="domainNames">The domain names in the
        /// certificate</param>
        /// <param name="privateKeyFormat">The private key format,
        /// PFX or PEM</param>
        /// <param name="password">The password for the private key
        /// </param>
        /// <returns>The new key pair</returns>
        Task<X509CertificatePrivateKeyPairModel> ProcessNewKeyPairRequestAsync(
            string groupId, string requestId, string applicationUri,
            string subjectName, string[] domainNames, PrivateKeyFormat privateKeyFormat,
            string password);

        /// <summary>
        /// Revoke a single certificate.
        /// Creates a new CRL version Issuer CA matching the certificate.
        /// </summary>
        /// <param name="groupId">The group Id</param>
        /// <param name="certificate">The certificate to revoke</param>
        /// <returns>The new CRL version</returns>
        Task<X509CrlModel> RevokeSingleCertificateAsync(string groupId,
            X509CertificateModel certificate);

        /// <summary>
        /// Revoke a group of certificates.
        /// Matches certificates with all active Issuer CA versions.
        /// Creates a new CRL for all Issuer CA versions.
        /// </summary>
        /// <param name="groupId">The group Id</param>
        /// <param name="certificates">The certificates to revoke</param>
        /// <returns>Returns certificates which could not be revoked
        /// </returns>
        Task<X509CertificateCollectionModel> RevokeCertificatesAsync(
            string groupId, X509CertificateCollectionModel certificates);

        /// <summary>
        /// Creates a new self signed Issuer CA certificate and an empty CRL.
        /// Uses subject and lifetime parameters of group configuration.
        /// </summary>
        /// <param name="groupId">The group groupId</param>
        /// <returns>The new Issuer CA cert</returns>
        Task<X509CertificateModel> GenerateNewIssuerCACertificateAsync(
            string groupId);

        /// <summary>
        /// Load the private key of a request from secure storage.
        /// </summary>
        /// <param name="groupId">The group groupId</param>
        /// <param name="requestId">The request groupId</param>
        /// <param name="privateKeyFormat">The format of the private
        /// key</param>
        /// <returns></returns>
        Task<byte[]> GetPrivateKeyAsync(string groupId, string requestId,
            PrivateKeyFormat privateKeyFormat);

        /// <summary>
        /// Accept and thus disable a private key.
        /// Returns the private key and tags the key as
        /// accepted/disabled.
        /// </summary>
        /// <param name="groupId">The group groupId</param>
        /// <param name="requestId">The request groupId</param>
        /// <returns>The private key</returns>
        Task AcceptPrivateKeyAsync(string groupId, string requestId);

        /// <summary>
        /// Delete a private key.
        /// Physically deletes the private key from secure storage.
        /// </summary>
        /// <param name="groupId">The group groupId</param>
        /// <param name="requestId">The request groupId</param>
        Task DeletePrivateKeyAsync(string groupId, string requestId);
    }
}
