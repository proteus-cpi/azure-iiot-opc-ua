// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace Microsoft.Azure.IIoT.OpcUa.Vault.KeyVault.Clients {
    using Microsoft.Azure.IIoT.OpcUa.Vault.KeyVault;
    using Microsoft.Azure.IIoT.OpcUa.Vault.KeyVault.Models;
    using Microsoft.Azure.IIoT.OpcUa.Vault.Models;
    using Microsoft.Azure.IIoT.Storage;
    using Microsoft.Azure.IIoT.Exceptions;
    using Microsoft.Azure.IIoT.Utils;
    using Microsoft.Azure.KeyVault;
    using Microsoft.Azure.KeyVault.Models;
    using Microsoft.Azure.KeyVault.WebKey;
    using Microsoft.Rest.Azure;
    using Opc.Ua;
    using Serilog;
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Security.Cryptography;
    using System.Security.Cryptography.X509Certificates;
    using System.Text;
    using System.Threading;
    using System.Threading.Tasks;

    /// <summary>
    /// A KeyVault service client.
    /// </summary>
    public class KeyVaultServiceClient : IKeyVault, IKeyValueStore, IPrivateKeyStore, 
        IDigestSigner, ICertificateFactory {

        /// <summary>
        /// Create the service client for KeyVault, with user or service
        /// credentials and specify the group secret key.
        /// </summary>
        /// <param name="config">The keyvault configuration.</param>
        /// <param name="provider"></param>
        /// <param name="logger">The logger.</param>
        public KeyVaultServiceClient(IVaultConfig config, Auth.ITokenProvider provider,
            ILogger logger) {
            _vaultBaseUrl = config.KeyVaultBaseUrl;
            _keyStoreIsHsm = config.KeyVaultIsHsm;
            _logger = logger;
            _keyVaultClient = new KeyVaultClient(async (_, resource, scope) => {
                var token = await provider.GetTokenForAsync(
                    resource, scope.YieldReturn());
                return token.RawToken;
            });
        }

        /// <inheritdoc/>
        public async Task<string> GetKeyValueAsync(
            string key, string contentType, CancellationToken ct) {
            if (string.IsNullOrEmpty(key)) {
                throw new ArgumentNullException(nameof(key));
            }
            var secret = await _keyVaultClient.GetSecretAsync(_vaultBaseUrl,
                key, ct);
            if (contentType != null) {
                if (secret.ContentType == null ||
                !secret.ContentType.EqualsIgnoreCase(contentType)) {
                    throw new ResourceInvalidStateException("Content type mismatch");
                }
            }
            return secret.Value;
        }

        /// <inheritdoc/>
        public async Task SetKeyValueAsync(string key, string value, DateTime? notBefore,
            DateTime? notAfter, string contentType, CancellationToken ct) {
            if (string.IsNullOrEmpty(key)) {
                throw new ArgumentNullException(nameof(key));
            }
            if (string.IsNullOrEmpty(value)) {
                throw new ArgumentNullException(nameof(value));
            }
            var secretAttributes = new SecretAttributes {
                Enabled = true,
                NotBefore = notBefore,
                Expires = notAfter
            };
            var secret = await _keyVaultClient.SetSecretAsync(_vaultBaseUrl,
                key, value, null, contentType, secretAttributes, ct);
        }

        /// <inheritdoc/>
        public async Task DeleteKeyValueAsync(string key, CancellationToken ct) {
            if (string.IsNullOrEmpty(key)) {
                throw new ArgumentNullException(nameof(key));
            }
            await _keyVaultClient.DeleteSecretAsync(_vaultBaseUrl, key, ct);
        }

        /// <inheritdoc/>
        public async Task<X509CertificateKeyIdPair> GetCertificateAsync(
            string certificateName, CancellationToken ct) {
            var certBundle = await _keyVaultClient.GetCertificateAsync(_vaultBaseUrl,
                certificateName, ct);
            return certBundle.ToStackModel();
        }

        /// <inheritdoc/>
        public async Task<(X509Certificate2Collection, string)> QueryCertificatesAsync(
            string certificateName, string thumbprint, string nextPageLink, int? pageSize,
            CancellationToken ct) {

            var certificates = new X509Certificate2Collection();
            pageSize = pageSize ?? kMaxResults;
            try {
                IPage<CertificateItem> certItems = null;
                if (nextPageLink != null) {
                    certItems = await _keyVaultClient.GetCertificateVersionsNextAsync(
                        nextPageLink, ct);
                }
                else {
                    certItems = await _keyVaultClient.GetCertificateVersionsAsync(
                        _vaultBaseUrl, certificateName, pageSize, ct);
                }
                while (certItems != null) {
                    foreach (var certItem in certItems) {
                        if (certItem.Attributes.Enabled ?? false) {
                            var certBundle = await _keyVaultClient.GetCertificateAsync(
                                certItem.Id, ct);
                            var cert = new X509Certificate2(certBundle.Cer);
                            if (thumbprint == null ||
                                cert.Thumbprint.EqualsIgnoreCase(thumbprint)) {
                                certificates.Add(cert);
                            }
                        }
                    }
                    if (certItems.NextPageLink != null) {
                        nextPageLink = certItems.NextPageLink;
                        certItems = null;
                        if (certificates.Count < pageSize) {
                            certItems = await _keyVaultClient.GetCertificateVersionsNextAsync(
                                nextPageLink, ct);
                            nextPageLink = null;
                        }
                    }
                    else {
                        certItems = null;
                        nextPageLink = null;
                    }
                }
            }
            catch (Exception ex) {
                _logger.Error(ex, "Error while loading the certificate versions for " +
                    certificateName + ".");
            }
            return (certificates, nextPageLink);
        }

        /// <inheritdoc/>
        public async Task<IList<X509CertificateKeyIdPair>> ListCertificatesAsync(
            string certificateName, CancellationToken ct) {
            var result = new List<X509CertificateKeyIdPair>();
            try {
                var certItems = await _keyVaultClient.GetCertificateVersionsAsync(
                    _vaultBaseUrl, certificateName, kMaxResults, ct);
                while (certItems != null) {
                    foreach (var certItem in certItems) {
                        var certBundle = await _keyVaultClient.GetCertificateAsync(
                            certItem.Id, ct);
                        result.Add(certBundle.ToStackModel());
                    }
                    if (certItems.NextPageLink != null) {
                        certItems = await _keyVaultClient.GetCertificateVersionsNextAsync(
                            certItems.NextPageLink, ct);
                    }
                    else {
                        certItems = null;
                    }
                }
            }
            catch (Exception ex) {
                _logger.Error(ex, "Error while loading the certificate versions for " +
                    certificateName + ".");
            }
            return result;
        }

#if UNUSED
        /// <summary>
        /// Load the signing CA certificate for signing operations.
        /// </summary>
        /// <param name="signingCertificateKey"></param>
        /// <param name="publicCert"></param>
        /// <param name="ct"></param>
        /// <returns></returns>
        // Task<X509Certificate2> LoadSigningCertificateAsync(
        //     string signingCertificateKey, X509Certificate2 publicCert,
        //     CancellationToken ct = default);
        public async Task<X509Certificate2> LoadSigningCertificateAsync(
            string signingCertificateKey, X509Certificate2 publicCert, CancellationToken ct) {
            if (publicCert == null) {
                throw new ArgumentNullException(nameof(publicCert));
            }
#if LOADPRIVATEKEY
            var secret = await _keyVaultClient.GetSecretAsync(signingCertificateKey, ct);
            if (secret.ContentType == CertificateContentType.Pfx) {
                var certBlob = Convert.FromBase64String(secret.Value);
                return CertificateFactory.CreateCertificateFromPKCS12(certBlob, string.Empty);
            }
            else if (secret.ContentType == CertificateContentType.Pem) {
                var privateKey = Encoding.UTF8.GetBytes(secret.Value.ToCharArray());
                return CertificateFactory.CreateCertificateWithPEMPrivateKey(publicCert, privateKey, string.Empty);
            }
            throw new NotImplementedException("Unknown content type: " + secret.ContentType);
#else
            ct.ThrowIfCancellationRequested();
            _logger.Error("Error in LoadSigningCertificateAsync " + signingCertificateKey + "." +
                "Loading the private key is not permitted.", signingCertificateKey);
            await Task.FromException(new NotSupportedException(
                "Loading the private key from key Vault is not permitted."));
            return null;
#endif
        }
#endif

        /// <inheritdoc/>
        public async Task<byte[]> SignDigestAsync(string signingKey, byte[] digest,
            HashAlgorithmName hashAlgorithm, RSASignaturePadding padding, CancellationToken ct) {
            string algorithm;

            if (padding == RSASignaturePadding.Pkcs1) {
                if (hashAlgorithm == HashAlgorithmName.SHA256) {
                    algorithm = JsonWebKeySignatureAlgorithm.RS256;
                }
                else if (hashAlgorithm == HashAlgorithmName.SHA384) {
                    algorithm = JsonWebKeySignatureAlgorithm.RS384;
                }
                else if (hashAlgorithm == HashAlgorithmName.SHA512) {
                    algorithm = JsonWebKeySignatureAlgorithm.RS512;
                }
                else {
                    _logger.Error("Error in SignDigestAsync {signingKey}." +
                        "Unsupported hash algorithm used.", signingKey);
                    throw new ArgumentOutOfRangeException(nameof(hashAlgorithm));
                }
            }
#if FUTURE
            else if (padding == RSASignaturePadding.Pss) {
                if (hashAlgorithm == HashAlgorithmName.SHA256) {
                    algorithm = JsonWebKeySignatureAlgorithm.PS256;
                }
                else if (hashAlgorithm == HashAlgorithmName.SHA384) {
                    algorithm = JsonWebKeySignatureAlgorithm.PS384;
                }
                else if (hashAlgorithm == HashAlgorithmName.SHA512) {
                    algorithm = JsonWebKeySignatureAlgorithm.PS512;
                }
                else {
                    throw new ArgumentOutOfRangeException(nameof(hashAlgorithm));
                }
            }
#endif
            else {
                _logger.Error("Error in SignDigestAsync {padding}." +
                    "Unsupported padding algorithm used.", padding);
                throw new ArgumentOutOfRangeException(nameof(padding));
            }

            var result = await _keyVaultClient.SignAsync(
                signingKey, algorithm, digest, ct);
            return result.Result;
        }

        /// <inheritdoc/>
        public async Task ImportCertificateAsync(string certificateName,
            X509Certificate2Collection certificates, bool trusted, CancellationToken ct) {
            if (string.IsNullOrEmpty(certificateName)) {
                throw new ArgumentNullException(nameof(certificateName));
            }
            if (certificates == null) {
                throw new ArgumentNullException(nameof(certificates));
            }
            if (certificates.Count == 0) {
                throw new ArgumentException("Empty certificate collection");
            }
            var certificate = certificates[0];
            var attributes = CreateCertificateAttributes(certificate.NotBefore,
                certificate.NotAfter);
            var policy = CreateCertificatePolicy(certificate, true,
                _keyStoreIsHsm);

            var tags = CreateCertificateTags(certificateName, trusted);
            await _keyVaultClient.ImportCertificateAsync(_vaultBaseUrl, certificateName,
                certificates, policy, attributes, tags, ct);
        }

        /// <inheritdoc/>
        public async Task<X509Certificate2> CreateCertificateAsync(string certificateName,
            string subject, DateTime notBefore, DateTime notAfter, int keySize,
            int hashSize, bool trusted, string crlDistributionPoint, CancellationToken ct) {
            if (string.IsNullOrEmpty(certificateName)) {
                throw new ArgumentNullException(nameof(certificateName));
            }

            // delete pending operations
            await Try.Async(() => _keyVaultClient.DeleteCertificateOperationAsync(_vaultBaseUrl,
                certificateName));

            string caTempCertIdentifier = null;
            try {
                // policy self signed, new key
                var policySelfSignedNewKey = CreateCertificatePolicy(subject, keySize, true, false);
                var tempAttributes = CreateCertificateAttributes(
                    DateTime.UtcNow.AddMinutes(-10), DateTime.UtcNow.AddMinutes(10));
                var createKey = await _keyVaultClient.CreateCertificateAsync(
                    _vaultBaseUrl, certificateName, policySelfSignedNewKey, tempAttributes, null, ct);
                CertificateOperation operation;
                do {
                    await Task.Delay(1000);
                    operation = await _keyVaultClient.GetCertificateOperationAsync(
                        _vaultBaseUrl, certificateName, ct);
                } while (operation.Status == "inProgress" && !ct.IsCancellationRequested);
                if (operation.Status != "completed") {
                    throw new CryptographicUnexpectedOperationException(
                        "Failed to create new key pair.");
                }
                var createdCertificateBundle = await _keyVaultClient.GetCertificateAsync(
                    _vaultBaseUrl, certificateName);
                var caCertKeyIdentifier = createdCertificateBundle.KeyIdentifier.Identifier;
                caTempCertIdentifier = createdCertificateBundle.CertificateIdentifier.Identifier;

                // policy unknown issuer, reuse key
                var policyUnknownReuse = CreateCertificatePolicy(subject, keySize, false, true);
                var attributes = CreateCertificateAttributes(notBefore, notAfter);
                var tags = CreateCertificateTags(certificateName, trusted);

                // create the CSR
                var createResult = await _keyVaultClient.CreateCertificateAsync(
                    _vaultBaseUrl, certificateName, policyUnknownReuse, attributes, tags, ct);
                if (createResult.Csr == null) {
                    throw new CryptographicUnexpectedOperationException(
                        "Failed to read CSR from CreateCertificate.");
                }

                // decode the CSR and verify consistency
                var info = createResult.Csr.ToCertificationRequestInfo();

                // create the self signed root CA cert
                var publicKey = info.SubjectPublicKeyInfo.GetRSAPublicKey();
                var signedcert = await CertificateFactory2.CreateSignedRootCertificateAsync(
                    subject, (ushort)keySize, notBefore, notAfter, (ushort)hashSize, 
                    publicKey, this, caCertKeyIdentifier, crlDistributionPoint);

                // merge Root CA cert with
                var mergeResult = await _keyVaultClient.MergeCertificateAsync(_vaultBaseUrl,
                    certificateName, new X509Certificate2Collection(signedcert));
                return signedcert;
            }
            catch (KeyVaultErrorException kex) {
                throw new ExternalDependencyException(
                    "Failed to create new Root CA certificate", kex);
            }
            finally {
                if (caTempCertIdentifier != null) {
                    // disable the temp cert for self signing operation
                    var attr = new CertificateAttributes {
                        Enabled = false
                    };
                    await Try.Async(() => _keyVaultClient.UpdateCertificateAsync(
                        caTempCertIdentifier, null, attr));
                }
            }
        }

#if UNUSED
        /// <inheritdoc/>
        public async Task<X509Certificate2> CreateSignedKeyPairCertAsync(
            string caCertId, X509Certificate2 issuerCert, string signingKeyId,
            string applicationUri, string applicationName, string subjectName,
            string[] domainNames, DateTime notBefore, DateTime notAfter, int keySize,
            int hashSize, string authorityInformationAccess,
            CancellationToken ct) {
            CertificateOperation createResult;
            var certificateName = GetKeyStoreName(caCertId, Guid.NewGuid().ToString());
            try {
                // policy unknown issuer, new key, exportable
                var policyUnknownNewExportable = CreateCertificatePolicy(
                    subjectName, keySize, false, false, true);
                var attributes = CreateCertificateAttributes(notBefore, notAfter);

                // create the CSR
                createResult = await _keyVaultClient.CreateCertificateAsync(
                    _vaultBaseUrl, certificateName, policyUnknownNewExportable, attributes,
                    null, ct);
                if (createResult.Csr == null) {
                    throw new CryptographicUnexpectedOperationException(
                        "Failed to read CSR from CreateCertificate.");
                }

                // decode the CSR and verify consistency
                var info = createResult.Csr.ToCertificationRequestInfo();

                // create the self signed app cert
                var publicKey = info.SubjectPublicKeyInfo.GetRSAPublicKey();
                var signedcert = await CertUtils.CreateSignedCertificate(
                    applicationUri, applicationName, subjectName, domainNames,
                    (ushort)keySize, notBefore, notAfter, (ushort)hashSize,
                    issuerCert, publicKey, this, signingKeyId, false, authorityInformationAccess);

                // merge signed cert with keystore
                var mergeResult = await _keyVaultClient.MergeCertificateAsync(
                    _vaultBaseUrl, certificateName, new X509Certificate2Collection(signedcert));

                X509Certificate2 keyPair = null;
                var secret = await _keyVaultClient.GetSecretAsync(
                    mergeResult.SecretIdentifier.Identifier, ct);
                if (secret.ContentType == CertificateContentType.Pfx) {
                    var certBlob = Convert.FromBase64String(secret.Value);
                    keyPair = CertificateFactory.CreateCertificateFromPKCS12(
                        certBlob, string.Empty);
                }
                else if (secret.ContentType == CertificateContentType.Pem) {
                    var encoder = Encoding.UTF8;
                    var privateKey = encoder.GetBytes(secret.Value.ToCharArray());
                    keyPair = CertificateFactory.CreateCertificateWithPEMPrivateKey(
                        signedcert, privateKey, string.Empty);
                }
                return keyPair;
            }
            catch {
                throw new ExternalDependencyException(
                    "Failed to create new key pair certificate");
            }
            finally {
                var deletedCertBundle = await _keyVaultClient.DeleteCertificateAsync(
                    _vaultBaseUrl, certificateName, ct);
                await Try.Async(() => _keyVaultClient.PurgeDeletedCertificateAsync(
                    _vaultBaseUrl, certificateName, ct));
            }
        }
#endif

        /// <inheritdoc/>
        public async Task ImportCrlAsync(string certificateName, string thumbPrint,
            X509CRL crl, CancellationToken ct) {
            try {
                var crlId = GetCrlId(certificateName, thumbPrint);
                var secretAttributes = new SecretAttributes {
                    Enabled = true,
                    NotBefore = crl.UpdateTime
                };

                // do not set tag for a CRL, the CA cert is already tagged.
                var result = await _keyVaultClient.SetSecretAsync(_vaultBaseUrl,
                    crlId, Convert.ToBase64String(crl.RawData),
                    null, ContentEncodings.MimeTypeCrl, secretAttributes, ct);
            }
#pragma warning disable RECS0022 // A catch clause that catches System.Exception and has an empty body
            catch (Exception) {
#pragma warning restore RECS0022 // A catch clause that catches System.Exception and has an empty body
                // TODO: add logging (is this a fatal error?)
            }
        }

        /// <inheritdoc/>
        public async Task<X509Crl2> GetCrlAsync(string certificateName, string thumbPrint,
            CancellationToken ct) {
            var crlId = GetCrlId(certificateName, thumbPrint);
            return await GetCrlSecretAsync(crlId, ct);
        }

        /// <inheritdoc/>
        public async Task ImportKeyAsync(string keyId, byte[] privateKey,
            PrivateKeyFormat privateKeyFormat, CancellationToken ct) {
            if (string.IsNullOrEmpty(keyId)) {
                throw new ArgumentNullException(nameof(keyId));
            }
            var contentType = PrivateKeyFormatToContentType(privateKeyFormat);
            var now = DateTime.UtcNow;
            var secretAttributes = new SecretAttributes {
                Enabled = true,
                NotBefore = now
            };
            var result = await _keyVaultClient.SetSecretAsync(_vaultBaseUrl, keyId,
                contentType.EqualsIgnoreCase(ContentEncodings.MimeTypePfxCert) ?
                    Convert.ToBase64String(privateKey) : Encoding.ASCII.GetString(privateKey),
                null, contentType, secretAttributes, ct);
        }

        /// <inheritdoc/>
        public async Task<byte[]> GetKeyAsync(string keyId, PrivateKeyFormat privateKeyFormat, 
            CancellationToken ct) {
            if (string.IsNullOrEmpty(keyId)) {
                throw new ArgumentNullException(nameof(keyId));
            }
            var contentType = PrivateKeyFormatToContentType(privateKeyFormat);
            var secret = await _keyVaultClient.GetSecretAsync(
                _vaultBaseUrl, keyId, ct);
            if (secret.ContentType.EqualsIgnoreCase(contentType)) {
                if (secret.ContentType.EqualsIgnoreCase(ContentEncodings.MimeTypePfxCert)) {
                    return Convert.FromBase64String(secret.Value);
                }
                if (secret.ContentType.EqualsIgnoreCase(ContentEncodings.MimeTypePemCert)) {
                    return Encoding.ASCII.GetBytes(secret.Value);
                }
            }
            // throw
            return null;
        }

        /// <inheritdoc/>
        public async Task DisableKeyAsync(string keyId, CancellationToken ct) {
            if (string.IsNullOrEmpty(keyId)) {
                throw new ArgumentNullException(nameof(keyId));
            }
            var secretKeys = await _keyVaultClient.GetSecretVersionsAsync(
                _vaultBaseUrl, keyId, null, ct);
            while (secretKeys != null) {
                foreach (var secret in secretKeys) {
                    var secretAttributes = new SecretAttributes {
                        Enabled = false,
                        Expires = DateTime.UtcNow
                    };
                    await _keyVaultClient.UpdateSecretAsync(secret.Id, null,
                        secretAttributes, null, ct);
                }
                if (secretKeys.NextPageLink != null) {
                    secretKeys = await _keyVaultClient.GetSecretVersionsNextAsync(
                        secretKeys.NextPageLink, ct);
                }
                else {
                    secretKeys = null;
                }
            }
        }

        /// <inheritdoc/>
        public async Task DeleteKeyAsync(string keyId, CancellationToken ct) {
            if (string.IsNullOrEmpty(keyId)) {
                throw new ArgumentNullException(nameof(keyId));
            }
            await _keyVaultClient.DeleteSecretAsync(_vaultBaseUrl, keyId, ct);
        }

        /// <inheritdoc/>
        public async Task<KeyVaultTrustListModel> GetTrustListAsync(
            string certificateName, int? maxResults, string nextPageLink, CancellationToken ct) {

            var trustList = new KeyVaultTrustListModel(certificateName);
            if (maxResults == null) {
                maxResults = kMaxResults;
            }
            IPage<SecretItem> secretItems = null;
            if (nextPageLink != null) {
                // Continuation
                if (nextPageLink.Contains("/secrets")) {
                    secretItems = await _keyVaultClient.GetSecretsNextAsync(
                        nextPageLink, ct);
                }
                // else - secrets is still null and we continue certs below ...
            }
            else {
                secretItems = await _keyVaultClient.GetSecretsAsync(_vaultBaseUrl,
                    maxResults, ct);
            }

            // 1.) load all certs and crls tagged with id==Issuer or id==Trusted.
            var results = 0;
            while (secretItems != null) {
                foreach (var secretItem in secretItems.Where(s => s.Tags != null)) {
                    var tag = secretItem.Tags
                        .FirstOrDefault(x => certificateName.EqualsIgnoreCase(x.Key)).Value;
                    var issuer = tag == kTagIssuerList;
                    var trusted = tag == kTagTrustedList;
                    var certType = secretItem.ContentType.EqualsIgnoreCase(
                        ContentEncodings.MimeTypeCert);
                    var crlType = secretItem.ContentType.EqualsIgnoreCase(
                        ContentEncodings.MimeTypeCrl);
                    if (issuer || (trusted && (certType || crlType))) {
                        if (certType) {
                            var certCollection = issuer ?
                                trustList.IssuerCertificates : trustList.TrustedCertificates;
                            var cert = await GetCertSecretAsync(secretItem.Identifier.Name, ct);
                            certCollection.Add(cert);
                        }
                        else {
                            var crlCollection = issuer ?
                                trustList.IssuerCrls : trustList.TrustedCrls;
                            var crl = await GetCrlSecretAsync(secretItem.Identifier.Name, ct);
                            crlCollection.Add(crl);
                        }
                        results++;
                    }
                }
                if (secretItems.NextPageLink != null) {
                    if (results >= maxResults) {
                        trustList.NextPageLink = secretItems.NextPageLink;
                        return trustList;
                    }
                    secretItems = await _keyVaultClient.GetSecretsNextAsync(
                        secretItems.NextPageLink, ct);
                }
                else {
                    secretItems = null;
                }
            }

            // 2.) Then walk all CA cert versions and load all certs
            //     tagged with groupId==Issuer or groupId==Trusted.
            //     Crl is loaded too if CA cert is tagged.
            IPage<CertificateItem> certItems = null;
            if (nextPageLink != null) {
                certItems = await _keyVaultClient.GetCertificateVersionsNextAsync(
                    nextPageLink, ct);
            }
            else {
                certItems = await _keyVaultClient.GetCertificateVersionsAsync(
                    _vaultBaseUrl, certificateName, maxResults, ct);
            }
            while (certItems != null) {
                foreach (var certItem in certItems.Where(c => c.Tags != null)) {
                    var tag = certItem.Tags
                        .FirstOrDefault(x => certificateName.EqualsIgnoreCase(x.Key)).Value;
                    var issuer = tag == kTagIssuerList;
                    var trusted = tag == kTagTrustedList;

                    if (issuer || trusted) {
                        var certBundle = await _keyVaultClient.GetCertificateAsync(
                            certItem.Id, ct);
                        var cert = new X509Certificate2(certBundle.Cer);
                        var crl = await GetCrlAsync(certificateName, cert.Thumbprint, ct);
                        if (issuer) {
                            trustList.IssuerCertificates.Add(cert);
                            trustList.IssuerCrls.Add(crl);
                        }
                        else {
                            trustList.TrustedCertificates.Add(cert);
                            trustList.TrustedCrls.Add(crl);
                        }
                        results++;
                    }
                }
                if (certItems.NextPageLink != null) {
                    if (results >= maxResults) {
                        trustList.NextPageLink = certItems.NextPageLink;
                        return trustList;
                    }
                    certItems = await _keyVaultClient.GetCertificateVersionsNextAsync(
                        certItems.NextPageLink, ct);
                }
                else {
                    certItems = null;
                }
            }
            return trustList;
        }

        /// <inheritdoc/>
        public async Task PurgeAsync(string configId, string groupId, CancellationToken ct) {

            // Purge keys
            var secretItems = await _keyVaultClient.GetSecretsAsync(
                _vaultBaseUrl, kMaxResults, ct);
            while (secretItems != null) {
                foreach (var secretItem in secretItems.Where(s =>
                    ((s.ContentType.EqualsIgnoreCase(ContentEncodings.MimeTypeCrl) ||
                      s.ContentType.EqualsIgnoreCase(ContentEncodings.MimeTypePemCert) ||
                      s.ContentType.EqualsIgnoreCase(ContentEncodings.MimeTypePfxCert)) &&
                    (groupId == null ||
                    s.Identifier.Name.StartsWith(groupId, StringComparison.OrdinalIgnoreCase))) ||
                    s.Identifier.Name.Equals(configId, StringComparison.OrdinalIgnoreCase))) {

                    var deletedSecretBundle = await Try.Async(() => _keyVaultClient.DeleteSecretAsync(
                        _vaultBaseUrl, secretItem.Identifier.Name, ct));
                    await Try.Async(() => _keyVaultClient.PurgeDeletedSecretAsync(
                        _vaultBaseUrl, secretItem.Identifier.Name, ct));
                }

                if (secretItems.NextPageLink != null) {
                    secretItems = await _keyVaultClient.GetSecretsNextAsync(
                        secretItems.NextPageLink, ct);
                }
                else {
                    secretItems = null;
                }
            }

            // Purge certs
            var certItems = await _keyVaultClient.GetCertificatesAsync(
                _vaultBaseUrl, kMaxResults, true, ct);
            while (certItems != null) {
                foreach (var certItem in certItems) {
                    if (groupId == null || groupId.EqualsIgnoreCase(certItem.Identifier.Name)) {
                        var deletedCertBundle = await Try.Async(() => _keyVaultClient.DeleteCertificateAsync(
                            _vaultBaseUrl, certItem.Identifier.Name, ct));
                        await Try.Async(() => _keyVaultClient.PurgeDeletedCertificateAsync(
                            _vaultBaseUrl, certItem.Identifier.Name, ct));
                    }
                }
                if (certItems.NextPageLink != null) {
                    certItems = await _keyVaultClient.GetCertificatesNextAsync(
                        certItems.NextPageLink, ct);
                }
                else {
                    certItems = null;
                }
            }
        }


        /// <summary>
        /// Create certificate tags
        /// </summary>
        /// <param name="groupId"></param>
        /// <param name="trusted"></param>
        /// <returns></returns>
        private static Dictionary<string, string> CreateCertificateTags(string groupId,
            bool trusted) {
            var tags = new Dictionary<string, string> {
                [groupId] = trusted ? kTagTrustedList : kTagIssuerList
            };
            return tags;
        }

        /// <summary>
        /// Create certificate attributes
        /// </summary>
        /// <param name="notBefore"></param>
        /// <param name="notAfter"></param>
        /// <returns></returns>
        private static CertificateAttributes CreateCertificateAttributes(DateTime notBefore,
            DateTime notAfter) {
            var attributes = new CertificateAttributes {
                Enabled = true,
                NotBefore = notBefore,
                Expires = notAfter
            };
            return attributes;
        }

        /// <summary>
        /// Create certificate policy
        /// </summary>
        /// <param name="certificate"></param>
        /// <param name="selfSigned"></param>
        /// <param name="isHsm"></param>
        /// <returns></returns>
        private static CertificatePolicy CreateCertificatePolicy(X509Certificate2 certificate,
            bool selfSigned, bool isHsm) {
            int keySize;
            using (var rsa = certificate.GetRSAPublicKey()) {
                keySize = rsa.KeySize;
                return CreateCertificatePolicy(certificate.Subject, rsa.KeySize,
                    selfSigned, isHsm);
            }
        }

        /// <summary>
        /// Create certificate policy
        /// </summary>
        /// <param name="subject"></param>
        /// <param name="keySize"></param>
        /// <param name="selfSigned"></param>
        /// <param name="reuseKey"></param>
        /// <param name="exportable"></param>
        /// <param name="isHsm"></param>
        /// <returns></returns>
        private static CertificatePolicy CreateCertificatePolicy(string subject, int keySize,
            bool selfSigned, bool isHsm, bool reuseKey = false, bool exportable = false) {

            var policy = new CertificatePolicy {
                IssuerParameters = new IssuerParameters {
                    Name = selfSigned ? "Self" : "Unknown"
                },
                KeyProperties = new KeyProperties {
                    Exportable = exportable,
                    KeySize = keySize,
                    KeyType = (isHsm && !exportable) ? "RSA-HSM" : "RSA",
                    ReuseKey = reuseKey
                },
                SecretProperties = new SecretProperties {
                    ContentType = CertificateContentType.Pfx
                },
                X509CertificateProperties = new X509CertificateProperties {
                    Subject = subject
                }
            };
            return policy;
        }

        /// <summary>
        /// Get key store name
        /// </summary>
        /// <param name="id"></param>
        /// <param name="requestId"></param>
        /// <returns></returns>
        private static string GetKeyStoreName(string id, string requestId) {
            return id + "Key" + requestId;
        }

        /// <summary>
        /// Get crl name
        /// </summary>
        /// <param name="certificateName"></param>
        /// <param name="thumbprint"></param>
        /// <returns></returns>
        private static string GetCrlId(string certificateName, string thumbprint) {
            return certificateName + "Crl" + thumbprint;
        }

        /// <summary>
        /// Load crl
        /// </summary>
        /// <param name="secretIdentifier"></param>
        /// <param name="ct"></param>
        /// <returns></returns>
        private async Task<X509Crl2> GetCrlSecretAsync(string secretIdentifier,
            CancellationToken ct) {
            var secret = await _keyVaultClient.GetSecretAsync(
                _vaultBaseUrl, secretIdentifier, ct);
            if (secret.ContentType.EqualsIgnoreCase(ContentEncodings.MimeTypeCrl)) {
                var crlBlob = Convert.FromBase64String(secret.Value);
                return new X509Crl2(crlBlob);
            }
            return null;
        }

        /// <summary>
        /// Load cert secret
        /// </summary>
        /// <param name="secretIdentifier"></param>
        /// <param name="ct"></param>
        /// <returns></returns>
        private async Task<X509Certificate2> GetCertSecretAsync(string secretIdentifier,
            CancellationToken ct) {
            var secret = await _keyVaultClient.GetSecretAsync(
                _vaultBaseUrl, secretIdentifier, ct);
            if (secret.ContentType.EqualsIgnoreCase(ContentEncodings.MimeTypeCert)) {
                var certBlob = Convert.FromBase64String(secret.Value);
                return new X509Certificate2(certBlob);
            }
            return null;
        }

        /// <summary>
        /// Convert format to content type
        /// </summary>
        /// <param name="privateKeyFormat"></param>
        /// <returns></returns>
        private static string PrivateKeyFormatToContentType(PrivateKeyFormat privateKeyFormat) {
            switch (privateKeyFormat) {
                case PrivateKeyFormat.PFX:
                    return ContentEncodings.MimeTypePfxCert;
                case PrivateKeyFormat.PEM:
                    return ContentEncodings.MimeTypePemCert;
                default:
                    throw new Exception("Unknown Private Key format.");
            }
        }

        private const string kTagIssuerList = "Issuer";
        private const string kTagTrustedList = "Trusted";
        private const int kMaxResults = 5;
        private readonly string _vaultBaseUrl;
        private readonly bool _keyStoreIsHsm;
        private readonly ILogger _logger;
        private readonly IKeyVaultClient _keyVaultClient;
    }
}

