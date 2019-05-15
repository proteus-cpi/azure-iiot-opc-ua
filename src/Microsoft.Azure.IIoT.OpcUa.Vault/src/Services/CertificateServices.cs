// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------


namespace Microsoft.Azure.IIoT.OpcUa.Vault.Services {
    using Microsoft.Azure.IIoT.OpcUa.Vault.KeyVault;
    using Microsoft.Azure.IIoT.OpcUa.Vault.Models;
    using Microsoft.Azure.IIoT.OpcUa.Registry.Models;
    using Microsoft.Azure.IIoT.Exceptions;
    using Serilog;
    using System;
    using System.Collections.Generic;
    using System.Security.Cryptography;
    using System.Security.Cryptography.X509Certificates;
    using System.Threading;
    using System.Threading.Tasks;
    using Autofac;
    using Opc.Ua;

    /// <summary>
    /// Key Vault Certificate Group services
    /// </summary>
    public sealed class CertificateServices : IGroupServices, IStartable {

        /// <summary>
        /// Create services
        /// </summary>
        /// <param name="registry"></param>
        /// <param name="keyVault"></param>
        /// <param name="privateKeys"></param>
        /// <param name="config"></param>
        /// <param name="logger"></param>
        public CertificateServices(IGroupRegistry registry,
            IKeyVault keyVault, IPrivateKeyStore privateKeys, 
            IVaultConfig config, ILogger logger) {
            _config = config ?? throw new ArgumentNullException(nameof(config));
            _registry = registry ?? throw new ArgumentNullException(nameof(registry));
            _keyVault = keyVault ?? throw new ArgumentNullException(nameof(keyVault));
            _privateKeys = privateKeys ?? throw new ArgumentNullException(nameof(privateKeys));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        /// <inheritdoc/>
        public void Start() {
            InitializeAllGroupsAsync().Wait();
        }

        /// <inheritdoc/>
        public async Task<X509CertificateModel> ProcessSigningRequestAsync(
            string groupId, string applicationUri, byte[] certificateRequest) {
            var group = await GetGroupAsync(groupId);

            // Process certificate request
            var cert = await group.ProcessSigningRequestAsync(
                new ApplicationInfoModel { ApplicationUri = applicationUri }, null,
                certificateRequest);
            return cert.ToServiceModel();
        }

        /// <inheritdoc/>
        public async Task<X509CertificatePrivateKeyPairModel> ProcessNewKeyPairRequestAsync(
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
            string groupId, bool? withCertificates, string nextPageLink, int? pageSize) {
            var group = await GetGroupAsync(groupId);
            return await group.ListIssuerCACertificateVersionsAsync(withCertificates,
                nextPageLink, pageSize);
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
            await group.RevokeSingleCertificateAsync(certificate.ToStackModel());
            return group.Crl.ToServiceModel();
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
            var success = await group.GenerateNewIssuerCACertificateAsync();
            if (success) {
                return group.Certificate.ToServiceModel();
            }
            return null;
        }

        /// <summary>
        /// Start and init all groups
        /// </summary>
        /// <returns></returns>
        private async Task InitializeAllGroupsAsync() {
            var certificateGroupCollection = await _registry.ListGroupsAsync();
            foreach (var groupInfo in certificateGroupCollection.Groups) {
                CertificateGroup group = null;
                try {
                    group = new CertificateGroup(_keyVault, _privateKeys,
                        groupInfo, _logger, _config.ServiceHost);

                    _logger.Information("Initialize Certificate group {group} for subject {subject}",
                        groupInfo.Id, groupInfo.GetSubjectName());
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
                if (!await group.GenerateNewIssuerCACertificateAsync()) {
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
            var group = new CertificateGroup(_keyVault, _privateKeys, info, _logger, 
                _config.ServiceHost);
            await group.InitializeHandlesAndCreateCACertificateIfNotExistsAsync();
            return group;
        }

        /// <summary>
        /// A certificate group where the Issuer CA cert and Crl are stored.
        /// </summary>
        private sealed class CertificateGroup {

            /// <summary>
            /// The latest Crl of this cert group
            /// </summary>
            public X509CRL Crl { get; set; }

            /// <summary>
            /// The group certificate
            /// </summary>
            public X509Certificate2 Certificate { get; set; }

            /// <summary>
            /// Create group
            /// </summary>
            /// <param name="keyVault"></param>
            /// <param name="privateKeys"></param>
            /// <param name="configuration"></param>
            /// <param name="logger"></param>
            /// <param name="serviceHost"></param>
            public CertificateGroup(IKeyVault keyVault, IPrivateKeyStore privateKeys,
                CertificateGroupInfoModel configuration,
                ILogger logger, string serviceHost) {
                _logger = logger;
                _keyVault = keyVault;
                _serviceHost = serviceHost ?? "localhost";
                _configuration = configuration;
                _privateKeys = privateKeys;
            }

            /// <summary>
            /// Load assets
            /// </summary>
            /// <returns></returns>
            private async Task LoadPublicAssetsAsync() {
                if (Certificate == null || _caCertSecretIdentifier == null ||
                    _caCertKeyIdentifier == null ||
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
                    Certificate = result.Certificate;
                    if (Utils.CompareDistinguishedName(Certificate.Subject, _configuration.GetSubjectName())) {

                        // Set group handles
                        _caCertSecretIdentifier = result.SecretIdentifier;
                        _caCertKeyIdentifier = result.KeyIdentifier;

                        Crl = await _keyVault.GetCrlAsync(_configuration.Id, Certificate.Thumbprint);
                    }
                    else {
                        throw new ResourceInvalidStateException(
                            $"Key Vault certificate subject({Certificate.Subject}) does not match " +
                            $"cert group subject {_configuration.GetSubjectName()}");
                    }
                }
                catch (Exception ex) {
                    // Create new group certificate
                    _logger.Information("Create new issuer CA certificate for group. ", _configuration.Id);

                    if (!await GenerateNewIssuerCACertificateAsync(false)) {
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
            public async Task<bool> GenerateNewIssuerCACertificateAsync(bool locked = true) {
                if (locked) {
                    await _semaphoreSlim.WaitAsync();
                }
                try {
                    var notBefore = TrimmedNotBeforeDate();
                    var notAfter = notBefore.AddMonths(_configuration.IssuerCACertificateLifetime);

                    // build distribution endpoint, if configured
                    var crlDistributionPoint = _configuration.GetCrlDistributionPointUrl(_serviceHost);

                    // create new CA cert in HSM storage
                    Certificate = await _keyVault.CreateCertificateAsync(
                        _configuration.Id, _configuration.SubjectName, notBefore, notAfter,
                        _configuration.IssuerCACertificateKeySize,
                        _configuration.IssuerCACertificateHashSize, true, crlDistributionPoint);

                    // update keys, ready back latest version
                    var result = await _keyVault.GetCertificateAsync(
                        _configuration.Id);
                    if (!result.Certificate.RawData.SequenceEqualsSafe(Certificate.RawData)) {
                        // something went utterly wrong...
                        return false;
                    }

                    _caCertSecretIdentifier = result.SecretIdentifier;
                    _caCertKeyIdentifier = result.KeyIdentifier;

                    // create default revocation list and sign with KeyVault
                    Crl = CertUtils.RevokeCertificate(Certificate, null, null, notBefore,
                        DateTime.MinValue, _keyVault, _caCertKeyIdentifier,
                        _configuration.IssuerCACertificateHashSize);

                    // import crl
                    await _keyVault.ImportCrlAsync(_configuration.Id, Certificate.Thumbprint, Crl);
                    return true;
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
            public async Task RevokeSingleCertificateAsync(X509Certificate2 certificate) {
                await LoadPublicAssetsAsync();

                var certificates = new X509Certificate2Collection { certificate };
                var caCertKeyInfoCollection = await _keyVault.GetCertificateVersionsAsync(
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

                        // Get current crl for this group
                        var crl = await _keyVault.GetCrlAsync(_configuration.Id,
                            caCertKeyInfo.Certificate.Thumbprint);

                        // Revoke the certificate and update the crl
                        var crls = new List<X509CRL> { crl };
                        var newCrl = CertUtils.RevokeCertificate(caCertKeyInfo.Certificate, crls,
                            certificates, now, DateTime.MinValue, _keyVault, caCertKeyInfo.KeyIdentifier, 
                            _configuration.IssuerCACertificateHashSize);

                        // Import updated crl and read back as new group crl
                        await _keyVault.ImportCrlAsync(_configuration.Id,
                            caCertKeyInfo.Certificate.Thumbprint, newCrl);
                        Crl = await _keyVault.GetCrlAsync(_configuration.Id, Certificate.Thumbprint);
                    }
                }
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
                var caCertKeyInfoCollection = await _keyVault.GetCertificateVersionsAsync(
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

                    // Get current crl
                    var crl = await _keyVault.GetCrlAsync(_configuration.Id,
                        caCertKeyInfo.Certificate.Thumbprint);

                    // Revoke and update crl
                    var crls = new List<X509CRL> { crl };
                    var newCrl = CertUtils.RevokeCertificate(caCertKeyInfo.Certificate, crls,
                        caRevokeCollection, now, DateTime.MinValue, _keyVault, caCertKeyInfo.KeyIdentifier,
                        _configuration.IssuerCACertificateHashSize);

                    // Re-import crl
                    await _keyVault.ImportCrlAsync(_configuration.Id, caCertKeyInfo.Certificate.Thumbprint,
                        newCrl);

                    foreach (var cert in caRevokeCollection) {
                        remainingCertificates.Remove(cert);
                    }
                }

                // Re-read crl
                Crl = await _keyVault.GetCrlAsync(_configuration.Id, Certificate.Thumbprint);
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

                var notBefore = DateTime.UtcNow.AddDays(-1);

                // create public/private key pair
                using (var keyPair = RSA.Create(_configuration.DefaultCertificateKeySize)) {
                    await LoadPublicAssetsAsync();
                    var authorityInformationAccess = _configuration.GetAuthorityInformationAccessUrl(
                        _serviceHost);

                    // sign public key with KeyVault
                    var signedCert = await CertUtils.CreateSignedCertificate(
                        application.ApplicationUri, application.GetApplicationName(), subjectName,
                        domainNames, _configuration.DefaultCertificateKeySize,
                        notBefore, notBefore.AddMonths(_configuration.DefaultCertificateLifetime),
                        _configuration.DefaultCertificateHashSize, Certificate, keyPair,
                         _keyVault, _caCertKeyIdentifier, false, authorityInformationAccess);

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
                                privateKey = CertificateFactory.ExportPrivateKeyAsPEM(
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
            public async Task<X509CertificatePrivateKeyPairModel> ProcessNewKeyPairRequestKeyVaultAsync(
                ApplicationInfoModel application, string subjectName, string[] domainNames,
                PrivateKeyFormat privateKeyFormat, string privateKeyPassword) {

                var notBefore = TrimmedNotBeforeDate();
                await LoadPublicAssetsAsync();

                var authorityInformationAccess = _configuration.GetAuthorityInformationAccessUrl(
                    _serviceHost);

                // create new cert with KeyVault
                var certWithPrivateKey = await _keyVault.CreateSignedKeyPairCertAsync(
                    _configuration.Id, Certificate, application.ApplicationUri,
                    application.GetApplicationName(), subjectName, domainNames,
                    notBefore, notBefore.AddMonths(_configuration.DefaultCertificateLifetime),
                    _configuration.DefaultCertificateKeySize,
                    _configuration.DefaultCertificateHashSize, _caCertKeyIdentifier,
                    authorityInformationAccess);

                using (certWithPrivateKey) {
                    byte[] privateKey;
                    switch (privateKeyFormat) {
                        case PrivateKeyFormat.PFX:
                            privateKey = certWithPrivateKey.Export(X509ContentType.Pfx,
                                privateKeyPassword);
                            break;
                        case PrivateKeyFormat.PEM:
                            privateKey = CertificateFactory.ExportPrivateKeyAsPEM(
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

            /// <summary>
            /// Create issuer CA cert and default Crl offline, then import in KeyVault.
            /// Note: Sample only for reference, importing the private key is unsecure!
            /// </summary>
            /// <returns></returns>
            public async Task<bool> CreateImportedIssuerCACertificateAsync() {
                await _semaphoreSlim.WaitAsync();
                try {
                    var notBefore = TrimmedNotBeforeDate();
                    using (var caCert = CertificateFactory.CreateCertificate(null,
                        null, null, null, null, _configuration.SubjectName, null,
                        _configuration.IssuerCACertificateKeySize, notBefore,
                        _configuration.IssuerCACertificateLifetime,
                        _configuration.IssuerCACertificateHashSize, true, null, null)) {

                        // save only public key
                        Certificate = new X509Certificate2(caCert.RawData);

                        // initialize revocation list
                        Crl = CertificateFactory.RevokeCertificate(caCert, null, null);
                        if (Crl == null) {
                            return false;
                        }

                        // upload ca cert with private key
                        await _keyVault.ImportCertificateAsync(_configuration.Id,
                            new X509Certificate2Collection(caCert), true);
                        await _keyVault.ImportCrlAsync(_configuration.Id,
                            Certificate.Thumbprint, Crl);
                    }
                    return true;
                }
                finally {
                    _semaphoreSlim.Release();
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
                    GetPrivateKeyId(requestId), privateKey, privateKeyFormat, ct);
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
                    privateKeyFormat, ct);
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

                // Create Key vault signer
                var signatureGenerator = new SignatureGenerator(
                    _keyVault, _caCertKeyIdentifier, Certificate);

                // Create certificate locally
                var publicKey = CertUtils.GetRSAPublicKey(info.SubjectPublicKeyInfo);
                return await CertUtils.CreateSignedCertificate(application.ApplicationUri,
                    application.GetApplicationName(), info.Subject.ToString(), domainNames,
                    _configuration.DefaultCertificateKeySize, notBefore,
                    notBefore.AddMonths(_configuration.DefaultCertificateLifetime),
                    _configuration.DefaultCertificateHashSize, Certificate,
                    publicKey, _keyVault, _caCertKeyIdentifier, false, 
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
                var certificate = Certificate;
                if (thumbprint != null &&
                    !thumbprint.EqualsIgnoreCase(Certificate.Thumbprint)) {
                    try {
                        var (collection, nextLink) =
                            await _keyVault.ListCertificatesAsync(
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
            /// <param name="withCertificates"></param>
            /// <param name="nextPageLink"></param>
            /// <param name="pageSize"></param>
            /// <returns></returns>
            public async Task<X509CertificateCollectionModel> ListIssuerCACertificateVersionsAsync(
                bool? withCertificates, string nextPageLink, int? pageSize) {
                var (result, nextLink) = await _keyVault.ListCertificatesAsync(
                    _configuration.Id, null, nextPageLink, pageSize);
                if (withCertificates ?? false) {
                    // TODO: implement withCertificates
                }
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
                var crl = Crl;
                if (thumbprint != null && !thumbprint.EqualsIgnoreCase(Certificate.Thumbprint)) {
                    // TODO: implement paging (low priority, only when long chains are expected)
                    try {
                        crl = await _keyVault.GetCrlAsync(_configuration.Id, thumbprint);
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

            private string _caCertSecretIdentifier;
            private string _caCertKeyIdentifier;
            private DateTime _lastUpdate;

            private readonly ILogger _logger;
            private readonly IKeyVault _keyVault;
            private readonly string _serviceHost;
            private readonly CertificateGroupInfoModel _configuration;
            private readonly IPrivateKeyStore _privateKeys;
            private readonly SemaphoreSlim _semaphoreSlim = new SemaphoreSlim(1, 1);
        }

        private readonly IVaultConfig _config;
        private readonly IKeyVault _keyVault;
        private readonly IPrivateKeyStore _privateKeys;
        private readonly ILogger _logger;
        private readonly IGroupRegistry _registry;
    }
}
