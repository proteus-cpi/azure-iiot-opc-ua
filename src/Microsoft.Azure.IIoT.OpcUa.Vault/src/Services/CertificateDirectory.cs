// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace Microsoft.Azure.IIoT.OpcUa.Vault.Services {
    using Microsoft.Azure.IIoT.OpcUa.Vault.Models;
    using Microsoft.Azure.IIoT.OpcUa.Registry.Models;
    using Microsoft.Azure.IIoT.Crypto;
    using Microsoft.Azure.IIoT.Crypto.KeyVault;
    using Microsoft.Azure.IIoT.Crypto.Models;
    using Microsoft.Azure.IIoT.Exceptions;
    using Autofac;
    using Opc.Ua;
    using Serilog;
    using System;
    using System.Collections.Generic;
    using System.Security.Cryptography;
    using System.Security.Cryptography.X509Certificates;
    using System.Threading;
    using System.Threading.Tasks;

    /// <summary>
    /// Key Vault Certificate Group services
    /// </summary>
    public sealed class CertificateDirectory : ICertificateDirectory, IStartable {

        /// <summary>
        /// Create services
        /// </summary>
        /// <param name="registry"></param>
        /// <param name="keyVault"></param>
        /// <param name="privateKeys"></param>
        /// <param name="crls"></param>
        /// <param name="revoker"></param>
        /// <param name="factory"></param>
        /// <param name="config"></param>
        /// <param name="logger"></param>
        public CertificateDirectory(IGroupRegistry registry, IKeyVaultService keyVault, 
            IPrivateKeyStore privateKeys, ICrlStore crls, ICertificateRevoker revoker,
            IApplicationCertificateFactory factory, IVaultConfig config, ILogger logger) {

            _config = config ?? throw new ArgumentNullException(nameof(config));
            _registry = registry ?? throw new ArgumentNullException(nameof(registry));
            _keyVault = keyVault ?? throw new ArgumentNullException(nameof(keyVault));
            _crls = crls ?? throw new ArgumentNullException(nameof(crls));
            _revoker = revoker ?? throw new ArgumentNullException(nameof(revoker));
            _factory = factory ?? throw new ArgumentNullException(nameof(factory));
            _privateKeys = privateKeys ?? throw new ArgumentNullException(nameof(privateKeys));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        /// <inheritdoc/>
        public void Start() {
            InitializeAllGroupsAsync().Wait();
        }

        /// <inheritdoc/>
        public async Task<X509CertificateModel> StartSigningRequestAsync(
            string groupId, string applicationUri, byte[] certificateRequest) {
            var group = await GetGroupAsync(groupId);

            // Process certificate request
            var cert = await group.ProcessSigningRequestAsync(
                new ApplicationInfoModel { ApplicationUri = applicationUri }, null,
                certificateRequest);
            return cert.ToServiceModel();
        }

        /// <inheritdoc/>
        public async Task<X509CertificatePrivateKeyPairModel> StartNewKeyPairRequestAsync(
            string groupId, string requestId, string applicationUri, string subjectName,
            string[] domainNames, PrivateKeyFormat privateKeyFormat,
            string privateKeyPassword) {
            var group = await GetGroupAsync(groupId);

            // Process request and get key pair
            var keyPair = await group.ProcessNewKeyPairRequestAsync(
                new ApplicationInfoModel { ApplicationUri = applicationUri },
                subjectName, domainNames, privateKeyFormat, privateKeyPassword);

            // Import key pair
            await group.ImportPrivateKeyAsync(requestId, keyPair.PrivateKey,
                keyPair.PrivateKeyFormat);
            return keyPair;
        }

        /// <inheritdoc/>
        public async Task<X509CertificateCollectionModel> ListIssuerCACertificateVersionsAsync(
            string groupId, string nextPageLink, int? pageSize) {
            var group = await GetGroupAsync(groupId);
            return await group.ListIssuerCACertificateVersionsAsync(nextPageLink, pageSize);
        }

        /// <inheritdoc/>
        public async Task<X509CertificateCollectionModel> GetIssuerCACertificateChainAsync(
            string groupId, string thumbPrint, string nextPageLink, int? pageSize) {
            var group = await GetGroupAsync(groupId);
            return await group.GetIssuerCACertificateChainAsync(thumbPrint,
                nextPageLink, pageSize);
        }

        /// <inheritdoc/>
        public async Task<X509CrlCollectionModel> GetIssuerCACrlChainAsync(
            string groupId, string thumbPrint, string nextPageLink, int? pageSize) {
            var group = await GetGroupAsync(groupId);
            return await group.GetIssuerCACrlChainAsync(thumbPrint,
                nextPageLink, pageSize);
        }

        /// <inheritdoc/>
        public async Task<byte[]> GetPrivateKeyAsync(string groupId, string requestId,
            PrivateKeyFormat privateKeyFormat) {
            var group = await GetGroupAsync(groupId);
            return await group.GetPrivateKeyAsync(requestId, privateKeyFormat);
        }

        /// <inheritdoc/>
        public async Task AcceptPrivateKeyAsync(string groupId, string requestId) {
            var group = await GetGroupAsync(groupId);
            await group.AcceptPrivateKeyAsync(requestId);
        }

        /// <inheritdoc/>
        public async Task DeletePrivateKeyAsync(string groupId, string requestId) {
            var group = await GetGroupAsync(groupId);
            await group.DeletePrivateKeyAsync(requestId);
        }

        /// <inheritdoc/>
        public async Task<TrustListModel> GetTrustListAsync(string groupId,
            string nextPageLink = null, int? pageSize = null) {
            var group = await GetGroupAsync(groupId);
            return await group.GetTrustListAsync(nextPageLink, pageSize);
        }

        /// <inheritdoc/>
        public async Task<X509CrlModel> RevokeSingleCertificateAsync(
            string groupId, X509CertificateModel certificate) {
            var group = await GetGroupAsync(groupId);
            var result = await group.RevokeSingleCertificateAsync(certificate.ToStackModel());
            return result.ToServiceModel();
        }

        /// <inheritdoc/>
        public async Task<X509CertificateCollectionModel> RevokeCertificatesAsync(
            string groupId, X509CertificateCollectionModel certificates) {
            var group = await GetGroupAsync(groupId);
            var result = await group.RevokeCertificatesAsync(certificates.ToStackModel());
            return result.ToServiceModel(null);
        }

        /// <inheritdoc/>
        public async Task<X509CertificateModel> GenerateNewIssuerCACertificateAsync(
            string groupId) {
            var group = await GetGroupAsync(groupId);
            var result = await group.GenerateNewIssuerCACertificateAsync();
            if (result == null) {
                throw new ResourceInvalidStateException("Failed to update root cert");
            }
            return result.ToServiceModel();
        }

        /// <summary>
        /// Start and init all groups  -- TODO Should be removed
        /// </summary>
        /// <returns></returns>
        private async Task InitializeAllGroupsAsync() {
            var certificateGroupCollection = await _registry.ListGroupIdsAsync();
            foreach (var groupId in certificateGroupCollection.Groups) {
                CertificateGroup group = null;
                try {
                    group = await GetGroupAsync(groupId);
                    _logger.Information("Initialize Certificate group {groupInfo}...",
                        groupId);
                    await group.InitializeHandlesAndCreateCACertificateIfNotExistsAsync();  
                    // group is ok
                    continue;
                }
                catch (Exception ex) {
                    _logger.Error("Failed to initialize certificate group. ", ex);
                    if (group == null) {
                        throw ex;
                    }
                }
                // Initialize group
                _logger.Information("Create new issuer CA certificate for group. ", group);
                if (null == await group.GenerateNewIssuerCACertificateAsync()) {
                    _logger.Error("Failed to create issuer CA certificate. ", group);
                }
            }
        }

        /// <summary>
        /// Open or create group
        /// </summary>
        /// <param name="groupId"></param>
        /// <returns></returns>
        private async Task<CertificateGroup> GetGroupAsync(string groupId) {
            var info = await _registry.GetGroupAsync(groupId);
            if (info == null) {
                throw new ResourceNotFoundException("The certificate group doesn't exist.");
            }
            var group = new CertificateGroup(_keyVault, _privateKeys, _crls, _revoker, _factory, info, _logger, 
                _config.ServiceHost);
            await group.InitializeHandlesAndCreateCACertificateIfNotExistsAsync();
            return group;
        }

        /// <summary>
        /// A certificate group where the Issuer CA cert and Crl are stored.
        /// </summary>
        private sealed class CertificateGroup {


            // TODO: remove
            private X509Crl2 _crl;

            /// <summary>
            /// Create group
            /// </summary>
            /// <param name="keyVault"></param>
            /// <param name="privateKeys"></param>
            /// <param name="crls"></param>
            /// <param name="revoker"></param>
            /// <param name="factory"></param>
            /// <param name="configuration"></param>
            /// <param name="logger"></param>
            /// <param name="serviceHost"></param>
            public CertificateGroup(IKeyVaultService keyVault, IPrivateKeyStore privateKeys,
                ICrlStore crls, ICertificateRevoker revoker, IApplicationCertificateFactory factory,
                CertificateGroupInfoModel configuration, ILogger logger, string serviceHost) {
                _logger = logger;
                _keyVault = keyVault;
                _factory = factory;
                _revoker = revoker;
                _crls = crls;
                _serviceHost = serviceHost ?? "localhost";
                _configuration = configuration;
                _privateKeys = privateKeys;
            }

            /// <summary>
            /// Load assets
            /// </summary>
            /// <returns></returns>
            private async Task LoadPublicAssetsAsync() {
                if ( _caCertIdentifier == null ||
                    TimeSpan.FromHours(1) < (DateTime.UtcNow - _lastUpdate)) {
                    await InitializeHandlesAndCreateCACertificateIfNotExistsAsync();
                    _lastUpdate = DateTime.UtcNow;
                }
            }

            /// <summary>
            /// Initialize the group
            /// </summary>
            /// <returns></returns>
            public async Task InitializeHandlesAndCreateCACertificateIfNotExistsAsync() {
                await _semaphoreSlim.WaitAsync();
                //while (true) { 
                try {
                    _logger.Verbose("Initialize Certificate group {group} for subject {subject}",
                        _configuration.Id, _configuration.GetSubjectName());
                    var result = await _keyVault.GetCertificateAsync(_configuration.Id);
                    if (Utils.CompareDistinguishedName(result.Certificate.Subject, _configuration.GetSubjectName())) {

                        // Set group handles
                        _caCertIdentifier = result;

                        _crl = await _crls.GetCrlAsync(_configuration.Id, result.Certificate.Thumbprint);
                    }
                    else {
                        throw new ResourceInvalidStateException(
                            $"Key Vault certificate subject({result.Certificate.Subject}) does not match " +
                            $"cert group subject {_configuration.GetSubjectName()}");
                    }
                }
                catch (Exception ex) {
                    // Create new group certificate
                    _logger.Information("Create new issuer CA certificate for group. ", _configuration.Id);

                    if (null == await GenerateNewIssuerCACertificateAsync(false)) {
                        _logger.Error(ex, "Failed to create issuer CA certificate. ", _configuration.Id);
                        // TODO: Try again - might already be initlized
                    }
                }
                finally {
                    _semaphoreSlim.Release();
                }
            }

            /// <summary>
            /// Create CA certificate and Crl with new private key in KeyVault HSM.
            /// </summary>
            /// <returns></returns>
            public async Task<X509Certificate2> GenerateNewIssuerCACertificateAsync(bool locked = true) {
                if (locked) {
                    await _semaphoreSlim.WaitAsync();
                }
                try {
                    var notBefore = TrimmedNotBeforeDate();
                    var notAfter = notBefore.AddMonths(_configuration.IssuerCACertificateLifetime);

                    // build distribution endpoint, if configured
                    var crlDistributionPoint = _configuration.GetCrlDistributionPointUrl(_serviceHost);

                    // create new CA cert in HSM storage
                    var certificate = await _keyVault.CreateCertificateAsync(
                        _configuration.Id, _configuration.SubjectName, notBefore, notAfter,
                        _configuration.IssuerCACertificateKeySize,
                        _configuration.IssuerCACertificateHashSize, true, crlDistributionPoint);

                    // update keys, ready back latest version
                    var result = await _keyVault.GetCertificateAsync(_configuration.Id);
                    if (!result.Certificate.RawData.SequenceEqualsSafe(certificate.Certificate.RawData)) {
                        // something went utterly wrong...
                        return null;
                    }

                    _caCertIdentifier = result;

                    // create default revocation list and sign with KeyVault
                    // TODO: Needs to be atomic
                    _crl = _revoker.CreateCrl(_caCertIdentifier, notBefore,
                        DateTime.MinValue);
                    // import crl
                    await _crls.SetCrlAsync(_configuration.Id, result.Certificate.Thumbprint, _crl);

                    return result.Certificate;
                }
                finally {
                    if (locked) {
                        _semaphoreSlim.Release();
                    }
                }
            }

            /// <summary>
            /// Revoke a certificate. Finds the matching CA cert version and updates Crl.
            /// </summary>
            /// <param name="certificate"></param>
            /// <returns></returns>
            public async Task<X509Crl2> RevokeSingleCertificateAsync(X509Certificate2 certificate) {
                await LoadPublicAssetsAsync();

                var certificates = new X509Certificate2Collection { certificate };
                var caCertKeyInfoCollection = await _keyVault.ListCertificatesAsync(
                    _configuration.Id);

                var authorityKeyIdentifier = certificate.FindAuthorityKeyIdentifier();
                var now = DateTime.UtcNow;
                foreach (var caCertKeyInfo in caCertKeyInfoCollection) {
                    var subjectKeyId = caCertKeyInfo.Certificate.FindSubjectKeyIdentifierExtension();
                    if (Utils.CompareDistinguishedName(
                            caCertKeyInfo.Certificate.Subject, certificate.Issuer) &&
                        authorityKeyIdentifier.SerialNumber
                            .EqualsIgnoreCase(caCertKeyInfo.Certificate.SerialNumber) &&
                        authorityKeyIdentifier.KeyId
                            .EqualsIgnoreCase(subjectKeyId.SubjectKeyIdentifier)) {

                        // TODO: Needs to be atomic

                        // Get current crl for this group
                        var crl = await _crls.GetCrlAsync(_configuration.Id,
                            caCertKeyInfo.Certificate.Thumbprint);

                        // Revoke the certificate and update the crl
                        var crls = new List<X509Crl2> { crl };
                        var newCrl = _revoker.RevokeCertificate(caCertKeyInfo, crls,
                            certificates, now, DateTime.MinValue, 
                            _configuration.IssuerCACertificateHashSize);
                        // Import updated crl and read back as new group crl
                        await _crls.SetCrlAsync(_configuration.Id,
                            caCertKeyInfo.Certificate.Thumbprint, newCrl);
                        _crl = await _crls.GetCrlAsync(_configuration.Id, _caCertIdentifier.Certificate.Thumbprint);

                        // end TODO
                    }
                }

                return _crl; // TODO get result
            }

            /// <summary>
            /// Revokes all certificates in the collection.
            /// Finds for each the matching CA cert version and updates Crl.
            /// </summary>
            /// <param name="certificates"></param>
            /// <returns></returns>
            public async Task<X509Certificate2Collection> RevokeCertificatesAsync(
                X509Certificate2Collection certificates) {

                var remainingCertificates = new X509Certificate2Collection(certificates);
                await LoadPublicAssetsAsync();

                // Get all certificates in the group
                var caCertKeyInfoCollection = await _keyVault.ListCertificatesAsync(
                    _configuration.Id);
                var now = DateTime.UtcNow;
                foreach (var caCertKeyInfo in caCertKeyInfoCollection) {
                    if (remainingCertificates.Count == 0) {
                        // No more to revoke
                        break;
                    }

                    // Get all to revoke that match any cert
                    var caRevokeCollection = new X509Certificate2Collection();
                    foreach (var cert in remainingCertificates) {
                        var authorityKeyIdentifier = cert.FindAuthorityKeyIdentifier();
                        var subjectKeyId = caCertKeyInfo.Certificate.FindSubjectKeyIdentifierExtension();
                        if (Utils.CompareDistinguishedName(
                                caCertKeyInfo.Certificate.Subject, cert.Issuer) &&
                            authorityKeyIdentifier.SerialNumber.EqualsIgnoreCase(
                                caCertKeyInfo.Certificate.SerialNumber) &&
                            authorityKeyIdentifier.KeyId.EqualsIgnoreCase(
                                subjectKeyId.SubjectKeyIdentifier)) {

                            // Add to be revoked
                            caRevokeCollection.Add(cert);
                        }
                    }
                    if (caRevokeCollection.Count == 0) {
                        // None found
                        continue;
                    }

                    // TODO: Needs to be atomic

                    // Get current crl
                    var crl = await _crls.GetCrlAsync(_configuration.Id,
                        caCertKeyInfo.Certificate.Thumbprint);
                    // Revoke and update crl
                    var crls = new List<X509Crl2> { crl };
                    var newCrl = _revoker.RevokeCertificate(_caCertIdentifier, crls,
                        caRevokeCollection, now, DateTime.MinValue, 
                        _configuration.IssuerCACertificateHashSize);
                    // Re-import crl
                    await _crls.SetCrlAsync(_configuration.Id, caCertKeyInfo.Certificate.Thumbprint,
                        newCrl);

                    // end TODO

                    foreach (var cert in caRevokeCollection) {
                        remainingCertificates.Remove(cert);
                    }
                }

                // Re-read crl
                _crl = await _crls.GetCrlAsync(_configuration.Id, 
                    _caCertIdentifier.Certificate.Thumbprint);
                return remainingCertificates;
            }

            /// <summary>
            /// Creates a new key pair with certificate offline and signs it with KeyVault.
            /// </summary>
            /// <param name="application"></param>
            /// <param name="subjectName"></param>
            /// <param name="domainNames"></param>
            /// <param name="privateKeyFormat"></param>
            /// <param name="privateKeyPassword"></param>
            /// <returns></returns>
            public async Task<X509CertificatePrivateKeyPairModel> ProcessNewKeyPairRequestAsync(
                ApplicationInfoModel application, string subjectName, string[] domainNames,
                PrivateKeyFormat privateKeyFormat, string privateKeyPassword) {

                // create public/private key pair
                using (var keyPair = RSA.Create(_configuration.DefaultCertificateKeySize)) {
                    await LoadPublicAssetsAsync();

                    // Get crl endpoint url
                    var authorityInformationAccess = _configuration.GetAuthorityInformationAccessUrl(
                        _serviceHost);

                    // Create new signed application certificate
                    var notBefore = DateTime.UtcNow.AddDays(-1);
                    var signedCert = await _factory.CreateSignedCertificateAsync(_caCertIdentifier,
                        keyPair, subjectName, 
                        application.ApplicationUri, application.GetApplicationName(), domainNames, 
                        _configuration.DefaultCertificateKeySize,
                        notBefore, notBefore.AddMonths(_configuration.DefaultCertificateLifetime),
                        _configuration.DefaultCertificateHashSize, authorityInformationAccess);

                    // Create a PEM or PFX
                    var certWithPrivateKey = signedCert.CreateCertificateWithPrivateKey(keyPair);
                    using (certWithPrivateKey) {
                        byte[] privateKey;
                        switch (privateKeyFormat) {
                            case PrivateKeyFormat.PFX:
                                privateKey = certWithPrivateKey.Export(X509ContentType.Pfx,
                                    privateKeyPassword);
                                break;
                            case PrivateKeyFormat.PEM:
                                privateKey = global::CertificateFactory.ExportPrivateKeyAsPEM(
                                    certWithPrivateKey);
                                break;
                            default:
                                throw new ArgumentNullException(nameof(privateKeyFormat),
                                    "Invalid private key format");
                        }
                        return new X509CertificatePrivateKeyPairModel {
                            Certificate = new X509Certificate2(certWithPrivateKey.RawData).ToServiceModel(),
                            PrivateKeyFormat = privateKeyFormat,
                            PrivateKey = privateKey
                        };
                    }
                }
            }

#if !UNUSED
            /// <summary>
            /// Creates a new key pair as KeyVault certificate and signs it with KeyVault.
            /// </summary>
            /// <param name="application"></param>
            /// <param name="subjectName"></param>
            /// <param name="domainNames"></param>
            /// <param name="privateKeyFormat"></param>
            /// <param name="privateKeyPassword"></param>
            /// <returns></returns>
            public async Task<X509CertificatePrivateKeyPairModel> ProcessNewKeyPairRequestWithKeyVaultAsync(
                ApplicationInfoModel application, string subjectName, string[] domainNames,
                PrivateKeyFormat privateKeyFormat, string privateKeyPassword) {

                var notBefore = TrimmedNotBeforeDate();
                var notAfter = notBefore.AddMonths(_configuration.DefaultCertificateLifetime);
                await LoadPublicAssetsAsync();

                var authorityInformationAccess = _configuration.GetAuthorityInformationAccessUrl(
                    _serviceHost);

                // create new cert with KeyVault
                var certificateName = GetPrivateKeyId(Guid.NewGuid().ToString());
                var certKeyPair = await _keyVault.CreateCertificateAsync(
                    certificateName, subjectName, notBefore, notAfter,
                    _configuration.DefaultCertificateKeySize, publicKey => 
                        // Create signed application certificate
                        _factory.CreateSignedCertificateAsync(_caCertIdentifier, publicKey,
                            subjectName, application.ApplicationUri,
                            application.GetApplicationName(), domainNames,
                            _configuration.DefaultCertificateKeySize, notBefore, notAfter,
                            _configuration.DefaultCertificateHashSize, authorityInformationAccess)
                    );
                if (certKeyPair?.Certificate == null) {
                    throw new CryptographicUnexpectedOperationException("Failed to create cert");
                }
                using (certKeyPair.Certificate) {
                    byte[] privateKey;
                    switch (privateKeyFormat) {
                        case PrivateKeyFormat.PFX:
                            privateKey = certKeyPair.Certificate.Export(X509ContentType.Pfx,
                                privateKeyPassword);
                            break;
                        case PrivateKeyFormat.PEM:
                            privateKey = global::CertificateFactory.ExportPrivateKeyAsPEM(
                                certKeyPair.Certificate);
                            break;
                        default:
                            throw new ArgumentNullException(nameof(privateKeyFormat),
                                "Invalid private key format");
                    }
                    return new X509CertificatePrivateKeyPairModel {
                        Certificate = new X509Certificate2(certKeyPair.Certificate.RawData).ToServiceModel(),
                        PrivateKeyFormat = privateKeyFormat,
                        PrivateKey = privateKey
                    };
                }
            }
#endif

            /// <summary>
            /// Stores the private key of a cert request in a Key Vault secret.
            /// </summary>
            /// <param name="requestId"></param>
            /// <param name="privateKey"></param>
            /// <param name="privateKeyFormat"></param>
            /// <param name="ct"></param>
            /// <returns></returns>
            public async Task ImportPrivateKeyAsync(string requestId, byte[] privateKey,
                PrivateKeyFormat privateKeyFormat, CancellationToken ct = default) {
                await _privateKeys.ImportKeyAsync(
                    GetPrivateKeyId(requestId), privateKey, (PrivateKeyEncoding)privateKeyFormat, ct);
            }

            /// <summary>
            /// Load the private key of a cert request from secret store
            /// </summary>
            /// <param name="requestId"></param>
            /// <param name="privateKeyFormat"></param>
            /// <param name="ct"></param>
            /// <returns></returns>
            public async Task<byte[]> GetPrivateKeyAsync(string requestId,
                PrivateKeyFormat privateKeyFormat, CancellationToken ct = default) {
                return await _privateKeys.GetKeyAsync(GetPrivateKeyId(requestId),
                    (PrivateKeyEncoding)privateKeyFormat, ct);
            }

            /// <summary>
            /// Accept the private key of a cert request from Key Vault secret.
            /// </summary>
            /// <param name="requestId"></param>
            /// <param name="ct"></param>
            /// <returns></returns>
            public async Task AcceptPrivateKeyAsync(string requestId,
                CancellationToken ct = default) {
                await _privateKeys.DisableKeyAsync(GetPrivateKeyId(requestId), ct);
            }

            /// <summary>
            /// Delete the private key of a cert request from Key Vault secret.
            /// </summary>
            /// <param name="requestId"></param>
            /// <param name="ct"></param>
            /// <returns></returns>
            public async Task DeletePrivateKeyAsync(string requestId,
                CancellationToken ct = default) {
                await _privateKeys.DeleteKeyAsync(GetPrivateKeyId(requestId), ct);
            }

            /// <summary>
            /// Process a signing request
            /// </summary>
            /// <param name="application"></param>
            /// <param name="domainNames"></param>
            /// <param name="certificateRequest"></param>
            /// <returns></returns>
            public async Task<X509Certificate2> ProcessSigningRequestAsync(
                ApplicationInfoModel application, string[] domainNames,
                byte[] certificateRequest) {
                var info = certificateRequest.ToCertificationRequestInfo();
                var altNameExtension = info.GetAltNameExtensionFromCSRInfo();
                if (altNameExtension != null) {
                    if (altNameExtension.Uris.Count > 0) {
                        if (!altNameExtension.Uris.Contains(application.ApplicationUri)) {
                            throw new UriFormatException("CSR AltNameExtension does not match " +
                                application.ApplicationUri);
                        }
                    }
                    if (altNameExtension.IPAddresses.Count > 0 ||
                        altNameExtension.DomainNames.Count > 0) {
                        var domainNameList = new List<string>();
                        domainNameList.AddRange(altNameExtension.DomainNames);
                        domainNameList.AddRange(altNameExtension.IPAddresses);
                        domainNames = domainNameList.ToArray();
                    }
                }

                var notBefore = DateTime.UtcNow.AddDays(-1);
                await LoadPublicAssetsAsync();

                // Create application certificate
                var publicKey = info.SubjectPublicKeyInfo.GetRSAPublicKey();
                return await _factory.CreateSignedCertificateAsync(_caCertIdentifier,
                    publicKey, info.Subject.ToString(), application.ApplicationUri,
                    application.GetApplicationName(), domainNames,
                    _configuration.DefaultCertificateKeySize, notBefore,
                    notBefore.AddMonths(_configuration.DefaultCertificateLifetime), 
                    _configuration.DefaultCertificateHashSize,
                    _configuration.GetAuthorityInformationAccessUrl(_serviceHost));
            }

            /// <summary>
            /// Reads the actual Issuer CA cert of the group.
            /// Or a historical CA cert by thumbprint.
            /// </summary>
            /// <param name="thumbprint">optional, the thumbprint of the certificate.</param>
            /// <param name="nextPageLink"></param>
            /// <param name="pageSize"></param>
            /// <returns>The issuer certificate</returns>
            public async Task<X509CertificateCollectionModel> GetIssuerCACertificateChainAsync(
                string thumbprint, string nextPageLink, int? pageSize) {
                await LoadPublicAssetsAsync();
                var certificate = _caCertIdentifier.Certificate;
                if (thumbprint != null &&
                    !thumbprint.EqualsIgnoreCase(certificate.Thumbprint)) {
                    try {
                        var (collection, nextLink) =
                            await _keyVault.QueryCertificatesAsync(
                                _configuration.Id, thumbprint, pageSize: 1);
                        if (collection.Count == 1) {
                            certificate = collection[0];
                        }
                    }
#pragma warning disable RECS0022 // A catch clause that catches System.Exception and has an empty body
                    catch {
#pragma warning restore RECS0022 // A catch clause that catches System.Exception and has an empty body
                    }
                    throw new ResourceNotFoundException("A Certificate for this thumbprint doesn't exist.");
                }
                return new X509Certificate2Collection(certificate).ToServiceModel(null);
            }

            /// <summary>
            /// List certificate versions
            /// </summary>
            /// <param name="nextPageLink"></param>
            /// <param name="pageSize"></param>
            /// <returns></returns>
            public async Task<X509CertificateCollectionModel> ListIssuerCACertificateVersionsAsync(
                string nextPageLink, int? pageSize) {
                var (result, nextLink) = await _keyVault.QueryCertificatesAsync(
                    _configuration.Id, null, nextPageLink, pageSize);
                return result.ToServiceModel(nextLink);
            }

            /// <summary>
            /// Get the actual Crl of a certificate group.
            /// Or the Crl of a historical Issuer CA cert by thumbprint.
            /// </summary>
            /// <param name="thumbprint">optional, the thumbprint of the certificate.</param>
            /// <param name="nextPageLink"></param>
            /// <param name="pageSize"></param>
            /// <returns></returns>
            public async Task<X509CrlCollectionModel> GetIssuerCACrlChainAsync(string thumbprint,
                string nextPageLink, int? pageSize) {
                await LoadPublicAssetsAsync();
                var crl = _crl;
                if (thumbprint != null && 
                    !thumbprint.EqualsIgnoreCase(_caCertIdentifier.Certificate.Thumbprint)) {
                    // TODO: implement paging (low priority, only when long chains are expected)
                    try {
                        crl = await _crls.GetCrlAsync(_configuration.Id, thumbprint);
                    }
                    catch (Exception ex) {
                        throw new ResourceNotFoundException("A CRL for this thumbprint was not found.", ex);
                    }
                    if (crl == null) {
                        throw new ResourceNotFoundException("A CRL for this thumbprint doesn't exist.");
                    }
                }
                return new X509CrlCollectionModel {
                    Chain = new List<X509CrlModel> { crl.ToServiceModel() }
                };
            }

            /// <summary>
            /// Get trust list from the group
            /// </summary>
            /// <param name="nextPageLink"></param>
            /// <param name="pageSize"></param>
            /// <returns></returns>
            public async Task<TrustListModel> GetTrustListAsync(
                string nextPageLink, int? pageSize) {



                var trustlist = await _keyVault.GetTrustListAsync(
                    _configuration.Id, pageSize, nextPageLink);
                return trustlist.ToServiceModel();
            }

            /// <summary>
            /// Get trimmed not before
            /// </summary>
            /// <returns></returns>
            private DateTime TrimmedNotBeforeDate() {
                var now = DateTime.UtcNow.AddDays(-1);
                return new DateTime(now.Year, now.Month, now.Day, 0, 0, 0, DateTimeKind.Utc);
            }

            /// <summary>
            /// Get key identifier
            /// </summary>
            /// <param name="requestId"></param>
            /// <returns></returns>
            private string GetPrivateKeyId(string requestId) {
                if (string.IsNullOrEmpty(requestId)) {
                    throw new ArgumentNullException(nameof(requestId));
                }
                return _configuration.Id + "Key" + requestId;
            }

            private X509CertificateKeyIdPair _caCertIdentifier;
            private DateTime _lastUpdate;

            private readonly IApplicationCertificateFactory _factory;
            private readonly ICertificateRevoker _revoker;
            private readonly ILogger _logger;
            private readonly IKeyVaultService _keyVault;
            private readonly string _serviceHost;
            private readonly CertificateGroupInfoModel _configuration;
            private readonly IPrivateKeyStore _privateKeys;
            private readonly ICrlStore _crls;
            private readonly SemaphoreSlim _semaphoreSlim = new SemaphoreSlim(1, 1);
        }

        private readonly IVaultConfig _config;
        private readonly IKeyVaultService _keyVault;
        private readonly ICrlStore _crls;
        private readonly ICertificateRevoker _revoker;
        private readonly IApplicationCertificateFactory _factory;
        private readonly IPrivateKeyStore _privateKeys;
        private readonly ILogger _logger;
        private readonly IGroupRegistry _registry;
    }
}
