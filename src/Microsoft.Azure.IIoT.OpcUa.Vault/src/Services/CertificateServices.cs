// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------


namespace Microsoft.Azure.IIoT.OpcUa.Vault.Services {
    using Microsoft.Azure.IIoT.OpcUa.Vault.KeyVault;
    using Microsoft.Azure.IIoT.OpcUa.Vault.Models;
    using Microsoft.Azure.IIoT.Exceptions;
    using Opc.Ua;
    using Opc.Ua.Gds;
    using Opc.Ua.Gds.Server;
    using Org.BouncyCastle.Pkcs;
    using System;
    using System.Collections.Generic;
    using System.Security.Cryptography;
    using System.Security.Cryptography.X509Certificates;
    using System.Threading;
    using System.Threading.Tasks;
    using Serilog;
    using Autofac;

    /// <summary>
    /// Key Vault Certificate Group services
    /// </summary>
    public sealed class CertificateServices : IGroupServices, IStartable {

        /// <summary>
        /// Create services
        /// </summary>
        /// <param name="registry"></param>
        /// <param name="client"></param>
        /// <param name="config"></param>
        /// <param name="logger"></param>
        public CertificateServices(IGroupRegistry registry,
            IKeyVaultServiceClient client, IVaultConfig config, ILogger logger) {
            _config = config ?? throw new ArgumentNullException(nameof(config));
            _registry = registry ?? throw new ArgumentNullException(nameof(registry));
            _client = client ?? throw new ArgumentNullException(nameof(client));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        /// <inheritdoc/>
        public void Start() => 
            InitializeAsync().Wait();

        /// <inheritdoc/>
        public async Task<X509CertificateModel> ProcessSigningRequestAsync(
            string groupId, string applicationUri, byte[] certificateRequest) {
            var group = await GetGroupAsync(groupId);
            var app = new ApplicationRecordDataType {
                ApplicationNames = new LocalizedTextCollection(),
                ApplicationUri = applicationUri
            };
            var cert = await group.SigningRequestAsync(app, null, certificateRequest);
            return cert.ToServiceModel();
        }

        /// <inheritdoc/>
        public async Task<X509CertificatePrivateKeyPairModel> ProcessNewKeyPairRequestAsync(
            string groupId, string requestId, string applicationUri, string subjectName,
            string[] domainNames, string privateKeyFormat, string privateKeyPassword) {
            var group = await GetGroupAsync(groupId);
            var app = new ApplicationRecordDataType {
                ApplicationNames = new LocalizedTextCollection(),
                ApplicationUri = applicationUri
            };
            var keyPair = await group.NewKeyPairRequestAsync(
                app, subjectName, domainNames, privateKeyFormat, privateKeyPassword);
            await group.ImportPrivateKeyAsync(requestId, keyPair.PrivateKey,
                keyPair.PrivateKeyFormat);
            return keyPair.ToServiceModel();
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
            return await group.GetIssuerCACertificateAsync(thumbPrint,
                nextPageLink, pageSize);
        }

        /// <inheritdoc/>
        public async Task<X509CrlCollectionModel> GetIssuerCACrlChainAsync(string groupId,
            string thumbPrint, string nextPageLink, int? pageSize) {
            var group = await GetGroupAsync(groupId);
            return await group.GetIssuerCACrlAsync(thumbPrint, 
                nextPageLink, pageSize);
        }

        /// <inheritdoc/>
        public async Task<byte[]> GetPrivateKeyAsync(string groupId, string requestId,
            string privateKeyFormat) {
            var group = await GetGroupAsync(groupId);
            return await group.LoadPrivateKeyAsync(requestId, privateKeyFormat);
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
            await group.RevokeCertificateAsync(certificate.ToStackModel());
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
        public async Task<X509CertificateModel> CreateIssuerCACertificateAsync(
            string groupId) {
            var group = await GetGroupAsync(groupId);
            var success = await group.CreateIssuerCACertificateAsync();
            if (success) {
                return group.Certificate.ToServiceModel();
            }
            return null;
        }

        /// <summary>
        /// Initialize
        /// </summary>
        /// <returns></returns>
        private async Task InitializeAsync() {
            var certificateGroupCollection = await _registry.ListGroupsAsync();
            foreach (var certificateGroupConfiguration in certificateGroupCollection.Groups) {
                CertificateGroup group = null;
                try {
                    group = new CertificateGroup(_client,
                        certificateGroupConfiguration, _config.ServiceHost);
                    await group.InitializeAsync();
#if LOADPRIVATEKEY
                    // test if private key can be loaded
                    await group.LoadSigningKeyAsync(null, null);
#endif
                    continue;
                }
                catch (Exception ex) {
                    _logger.Error("Failed to initialize certificate group. ", ex);
                    if (group == null) {
                        throw ex;
                    }
                }
                _logger.Information("Create new issuer CA certificate for group. ", group);
                if (!await group.CreateIssuerCACertificateAsync()) {
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
            var group = await _registry.GetGroupAsync(groupId);
            if (group == null) {
                throw new ResourceNotFoundException("The certificate group doesn't exist.");
            }
            return new CertificateGroup(_client, group, _config.ServiceHost);
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
            /// <param name="keyVaultServiceClient"></param>
            /// <param name="configuration"></param>
            /// <param name="serviceHost"></param>
            public CertificateGroup(IKeyVaultServiceClient keyVaultServiceClient,
                CertificateGroupInfoModel configuration, string serviceHost) {

                _keyVaultServiceClient = keyVaultServiceClient;
                _serviceHost = serviceHost ?? "localhost";
                _configuration = configuration;
            }

            /// <inheritdoc/>
            public async Task InitializeAsync() {
                await _semaphoreSlim.WaitAsync();
                try {
                    Utils.Trace(Utils.TraceMasks.Information, "InitializeCertificateGroup: {0}",
                        _configuration.GetSubjectName());
                    var result = await _keyVaultServiceClient.GetCertificateAsync(_configuration.Id)
                        ;
                    Certificate = new X509Certificate2(result.Cer);
                    if (Utils.CompareDistinguishedName(Certificate.Subject, _configuration.SubjectName)) {
                        _caCertSecretIdentifier = result.SecretIdentifier.Identifier;
                        _caCertKeyIdentifier = result.KeyIdentifier.Identifier;
                        Crl = await _keyVaultServiceClient.LoadIssuerCACrl(_configuration.Id, Certificate);
                    }
                    else {
                        throw new ResourceInvalidStateException(
                            $"Key Vault certificate subject({Certificate.Subject}) does not match " +
                            $"cert group subject {_configuration.SubjectName}");
                    }
                }
                catch (Exception e) {
                    _caCertSecretIdentifier = null;
                    _caCertKeyIdentifier = null;
                    Certificate = null;
                    Crl = null;
                    throw e;
                }
                finally {
                    _semaphoreSlim.Release();
                }
            }

#if UNUSED
        /// <summary>
        /// Create issuer CA cert and default Crl offline, then import in KeyVault.
        /// Note: Sample only for reference, importing the private key is unsecure!
        /// </summary>
        /// <returns></returns>
        public async Task<bool> CreateImportedIssuerCACertificateAsync() {
            await _semaphoreSlim.WaitAsync();
            try {
                var notBefore = TrimmedNotBeforeDate();
                using (var caCert = CertificateFactory.CreateCertificate(null, null, null,
                    null, null, Configuration.SubjectName, null, Configuration.IssuerCACertificateKeySize,
                    notBefore, Configuration.IssuerCACertificateLifetime, 
                    Configuration.IssuerCACertificateHashSize, true, null, null)) {

                    // save only public key
                    Certificate = new X509Certificate2(caCert.RawData);

                    // initialize revocation list
                    Crl = CertificateFactory.RevokeCertificate(caCert, null, null);
                    if (Crl == null) {
                        return false;
                    }

                    // upload ca cert with private key
                    await _keyVaultServiceClient.ImportIssuerCACertificate(Configuration.Id,
                        new X509Certificate2Collection(caCert), true);
                    await _keyVaultServiceClient.ImportIssuerCACrl(Configuration.Id,
                        Certificate, Crl);
                }
                return true;
            }
            finally {
                _semaphoreSlim.Release();
            }
        }
#endif

            /// <summary>
            /// Create CA certificate and Crl with new private key in KeyVault HSM.
            /// </summary>
            /// <returns></returns>
            public async Task<bool> CreateIssuerCACertificateAsync() {
                await _semaphoreSlim.WaitAsync();
                try {
                    var notBefore = TrimmedNotBeforeDate();
                    var notAfter = notBefore.AddMonths(_configuration.IssuerCACertificateLifetime);

                    // build distribution endpoint, if configured
                    var crlDistributionPoint = _configuration.GetCrlDistributionPointUrl(_serviceHost);

                    // create new CA cert in HSM storage
                    Certificate = await _keyVaultServiceClient.CreateCACertificateAsync(
                        _configuration.Id, _configuration.SubjectName, notBefore, notAfter,
                        _configuration.IssuerCACertificateKeySize, _configuration.IssuerCACertificateHashSize,
                        true, crlDistributionPoint);
                    // update keys, ready back latest version
                    var result = await _keyVaultServiceClient.GetCertificateAsync(
                        _configuration.Id);
                    if (!Utils.IsEqual(result.Cer, Certificate.RawData)) {
                        // something went utterly wrong...
                        return false;
                    }
                    _caCertSecretIdentifier = result.SecretIdentifier.Identifier;
                    _caCertKeyIdentifier = result.KeyIdentifier.Identifier;

                    // create default revocation list, sign with KeyVault
                    Crl = CertUtils.RevokeCertificate(Certificate, null, null, notBefore, DateTime.MinValue,
                        new KeyVaultSignatureGenerator(
                            _keyVaultServiceClient, _caCertKeyIdentifier, Certificate),
                        _configuration.IssuerCACertificateHashSize);

                    // upload crl
                    await _keyVaultServiceClient.ImportIssuerCACrl(
                        _configuration.Id, Certificate, Crl);
                    return true;
                }
                finally {
                    _semaphoreSlim.Release();
                }
            }

            /// <summary>
            /// Revoke a certificate. Finds the matching CA cert version and updates Crl.
            /// </summary>
            /// <returns></returns>
            public async Task RevokeCertificateAsync(X509Certificate2 certificate) {
                await LoadPublicAssetsAsync();
                var certificates = new X509Certificate2Collection { certificate };
                var caCertKeyInfoCollection = await _keyVaultServiceClient.ListCertificateVersionsKeyInfoAsync(
                    _configuration.Id);
                var authorityKeyIdentifier = certificate.FindAuthorityKeyIdentifier();
                var now = DateTime.UtcNow;
                foreach (var caCertKeyInfo in caCertKeyInfoCollection) {
                    var subjectKeyId = caCertKeyInfo.Certificate.FindSubjectKeyIdentifierExtension();
                    if (Utils.CompareDistinguishedName(caCertKeyInfo.Certificate.Subject, certificate.Issuer) &&
                        authorityKeyIdentifier.SerialNumber
                            .EqualsIgnoreCase(caCertKeyInfo.Certificate.SerialNumber) &&
                        authorityKeyIdentifier.KeyId
                            .EqualsIgnoreCase(subjectKeyId.SubjectKeyIdentifier)) {
                        var crl = await _keyVaultServiceClient.LoadIssuerCACrl(
                            _configuration.Id, caCertKeyInfo.Certificate);
                        var crls = new List<X509CRL> { crl };
                        var newCrl = CertUtils.RevokeCertificate(caCertKeyInfo.Certificate, crls,
                            certificates, now, DateTime.MinValue, new KeyVaultSignatureGenerator(
                                _keyVaultServiceClient, caCertKeyInfo.KeyIdentifier, caCertKeyInfo.Certificate),
                            _configuration.IssuerCACertificateHashSize);
                        await _keyVaultServiceClient.ImportIssuerCACrl(
                            _configuration.Id, caCertKeyInfo.Certificate, newCrl);
                        Crl = await _keyVaultServiceClient.LoadIssuerCACrl(_configuration.Id, Certificate);
                    }
                }
            }

            /// <summary>
            /// Revokes a certificate collection.
            /// Finds for each the matching CA cert version and updates Crl.
            /// </summary>
            /// <returns></returns>
            public async Task<X509Certificate2Collection> RevokeCertificatesAsync(
                X509Certificate2Collection certificates) {
                var remainingCertificates = new X509Certificate2Collection(certificates);
                await LoadPublicAssetsAsync();
                var caCertKeyInfoCollection = await _keyVaultServiceClient.ListCertificateVersionsKeyInfoAsync(
                    _configuration.Id);
                var now = DateTime.UtcNow;
                foreach (var caCertKeyInfo in caCertKeyInfoCollection) {
                    if (remainingCertificates.Count == 0) {
                        break;
                    }
                    var caRevokeCollection = new X509Certificate2Collection();
                    foreach (var cert in remainingCertificates) {
                        var authorityKeyIdentifier = cert.FindAuthorityKeyIdentifier();
                        var subjectKeyId = caCertKeyInfo.Certificate.FindSubjectKeyIdentifierExtension();
                        if (Utils.CompareDistinguishedName(caCertKeyInfo.Certificate.Subject, cert.Issuer) &&
                            authorityKeyIdentifier.SerialNumber.EqualsIgnoreCase(
                                caCertKeyInfo.Certificate.SerialNumber) &&
                            authorityKeyIdentifier.KeyId.EqualsIgnoreCase(
                                subjectKeyId.SubjectKeyIdentifier)) {
                            caRevokeCollection.Add(cert);
                        }
                    }
                    if (caRevokeCollection.Count == 0) {
                        continue;
                    }
                    var crl = await _keyVaultServiceClient.LoadIssuerCACrl(_configuration.Id,
                        caCertKeyInfo.Certificate);
                    var crls = new List<X509CRL> { crl };
                    var newCrl = CertUtils.RevokeCertificate(caCertKeyInfo.Certificate, crls,
                        caRevokeCollection, now, DateTime.MinValue, new KeyVaultSignatureGenerator(
                            _keyVaultServiceClient, caCertKeyInfo.KeyIdentifier, caCertKeyInfo.Certificate),
                        _configuration.IssuerCACertificateHashSize);
                    await _keyVaultServiceClient.ImportIssuerCACrl(
                        _configuration.Id, caCertKeyInfo.Certificate, newCrl);

                    foreach (var cert in caRevokeCollection) {
                        remainingCertificates.Remove(cert);
                    }
                }
                Crl = await _keyVaultServiceClient.LoadIssuerCACrl(_configuration.Id, Certificate);
                return remainingCertificates;
            }

            /// <summary>
            /// Creates a new key pair as KeyVault certificate and signs it with KeyVault.
            /// </summary>
            /// <returns></returns>
            public async Task<X509Certificate2KeyPair> NewKeyPairRequestKeyVaultCertAsync(
                ApplicationRecordDataType application, string subjectName, string[] domainNames,
                string privateKeyFormat, string privateKeyPassword) {

                await LoadPublicAssetsAsync();
                var notBefore = TrimmedNotBeforeDate();
                var notAfter = notBefore.AddMonths(_configuration.DefaultCertificateLifetime);

                var authorityInformationAccess = _configuration.GetAuthorityInformationAccessUrl(
                    _serviceHost);
                // create new cert with KeyVault
                using (var signedCertWithPrivateKey = await _keyVaultServiceClient.CreateSignedKeyPairCertAsync(
                    _configuration.Id, Certificate, application.ApplicationUri,
                    application.ApplicationNames.Count > 0 ?
                        application.ApplicationNames[0].Text : "ApplicationName",
                    subjectName, domainNames, notBefore, notAfter, _configuration.DefaultCertificateKeySize,
                    _configuration.DefaultCertificateHashSize, new KeyVaultSignatureGenerator(
                        _keyVaultServiceClient, _caCertKeyIdentifier, Certificate),
                    authorityInformationAccess)) {
                    byte[] privateKey;
                    if (privateKeyFormat == "PFX") {
                        privateKey = signedCertWithPrivateKey.Export(
                            X509ContentType.Pfx, privateKeyPassword);
                    }
                    else if (privateKeyFormat == "PEM") {
                        privateKey = CertificateFactory.ExportPrivateKeyAsPEM(
                            signedCertWithPrivateKey);
                    }
                    else {
                        throw new ServiceResultException(StatusCodes.BadInvalidArgument,
                            "Invalid private key format");
                    }
                    return new X509Certificate2KeyPair(
                        new X509Certificate2(signedCertWithPrivateKey.RawData),
                        privateKeyFormat, privateKey);
                }
            }

            /// <summary>
            /// Creates a new key pair with certificate offline and signs it with KeyVault.
            /// </summary>
            /// <returns></returns>
            public async Task<X509Certificate2KeyPair> NewKeyPairRequestAsync(
                ApplicationRecordDataType application, string subjectName, string[] domainNames,
                string privateKeyFormat, string privateKeyPassword) {
                if (!privateKeyFormat.Equals("PFX", StringComparison.OrdinalIgnoreCase) &&
                    !privateKeyFormat.Equals("PEM", StringComparison.OrdinalIgnoreCase)) {
                    throw new ServiceResultException(StatusCodes.BadInvalidArgument,
                        "Invalid private key format");
                }
                var notBefore = DateTime.UtcNow.AddDays(-1);
                // create public/private key pair
                using (var keyPair = RSA.Create(_configuration.DefaultCertificateKeySize)) {
                    await LoadPublicAssetsAsync();
                    var authorityInformationAccess = _configuration.GetAuthorityInformationAccessUrl(
                        _serviceHost);

                    // sign public key with KeyVault
                    var signedCert = await CertUtils.CreateSignedCertificate(
                        application.ApplicationUri, application.ApplicationNames.Count > 0 ?
                            application.ApplicationNames[0].Text : "ApplicationName",
                        subjectName, domainNames, _configuration.DefaultCertificateKeySize,
                        notBefore, notBefore.AddMonths(_configuration.DefaultCertificateLifetime),
                        _configuration.DefaultCertificateHashSize, Certificate, keyPair,
                        new KeyVaultSignatureGenerator(
                            _keyVaultServiceClient, _caCertKeyIdentifier, Certificate),
                        false, authorityInformationAccess);
                    // Create a PEM or PFX
                    using (var signedCertWithPrivateKey = signedCert.CreateCertificateWithPrivateKey(keyPair)) {
                        byte[] privateKey;
                        if (privateKeyFormat.Equals("PFX", StringComparison.OrdinalIgnoreCase)) {
                            privateKey = signedCertWithPrivateKey.Export(X509ContentType.Pfx, privateKeyPassword);
                        }
                        else if (privateKeyFormat.Equals("PEM", StringComparison.OrdinalIgnoreCase)) {
                            privateKey = CertificateFactory.ExportPrivateKeyAsPEM(signedCertWithPrivateKey);
                        }
                        else {
                            throw new ServiceResultException(StatusCodes.BadInvalidArgument,
                                "Invalid private key format");
                        }
                        return new X509Certificate2KeyPair(
                            new X509Certificate2(signedCertWithPrivateKey.RawData),
                            privateKeyFormat, privateKey);
                    }
                }
            }

            /// <summary>
            /// Stores the private key of a cert request in a Key Vault secret.
            /// </summary>
            public async Task ImportPrivateKeyAsync(string requestId,
                byte[] privateKey, string privateKeyFormat, CancellationToken ct = default) {
                await _keyVaultServiceClient.ImportKeySecretAsync(
                    _configuration.Id, requestId, privateKey, privateKeyFormat, ct);
            }

            /// <summary>
            /// Load the private key of a cert request from Key Vault secret.
            /// </summary>
            public async Task<byte[]> LoadPrivateKeyAsync(string requestId, string privateKeyFormat, 
                CancellationToken ct = default) {
                return await _keyVaultServiceClient.LoadKeySecretAsync( _configuration.Id, requestId,
                    privateKeyFormat, ct);
            }

            /// <summary>
            /// Accept the private key of a cert request from Key Vault secret.
            /// </summary>
            public async Task AcceptPrivateKeyAsync(string requestId, CancellationToken ct = default) {
                await _keyVaultServiceClient.InvalidateKeySecretAsync(_configuration.Id, requestId, ct);
            }

            /// <summary>
            /// Delete the private key of a cert request from Key Vault secret.
            /// </summary>
            public async Task DeletePrivateKeyAsync(string requestId, CancellationToken ct = default) {
                await _keyVaultServiceClient.DeleteKeySecretAsync(_configuration.Id, requestId, ct);
            }

            /// <inheritdoc/>
            public async Task<X509Certificate2> SigningRequestAsync(
                ApplicationRecordDataType application, string[] domainNames,
                byte[] certificateRequest) {
                try {
                    var pkcs10CertificationRequest = new Pkcs10CertificationRequest(
                        certificateRequest);
                    if (!pkcs10CertificationRequest.Verify()) {
                        throw new ServiceResultException(StatusCodes.BadInvalidArgument,
                            "CSR signature invalid.");
                    }

                    var info = pkcs10CertificationRequest.GetCertificationRequestInfo();
                    var altNameExtension = info.GetAltNameExtensionFromCSRInfo();
                    if (altNameExtension != null) {
                        if (altNameExtension.Uris.Count > 0) {
                            if (!altNameExtension.Uris.Contains(application.ApplicationUri)) {
                                throw new ServiceResultException(StatusCodes.BadCertificateUriInvalid,
                                    "CSR AltNameExtension does not match " + application.ApplicationUri);
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

                    var authorityInformationAccess = _configuration.GetAuthorityInformationAccessUrl(
                        _serviceHost);
                    var notBefore = DateTime.UtcNow.AddDays(-1);
                    await LoadPublicAssetsAsync();
                    var signingCert = Certificate;
                    {
                        var publicKey = CertUtils.GetRSAPublicKey(
                            info.SubjectPublicKeyInfo);
                        return await CertUtils.CreateSignedCertificate(application.ApplicationUri,
                            application.ApplicationNames.Count > 0 ?
                                application.ApplicationNames[0].Text : "ApplicationName",
                            info.Subject.ToString(), domainNames,
                            _configuration.DefaultCertificateKeySize, notBefore,
                            notBefore.AddMonths(_configuration.DefaultCertificateLifetime),
                            _configuration.DefaultCertificateHashSize, signingCert,
                            publicKey, new KeyVaultSignatureGenerator(
                                _keyVaultServiceClient, _caCertKeyIdentifier, signingCert),
                            false, authorityInformationAccess
                            );
                    }
                }
                catch (Exception ex) {
                    if (ex is ServiceResultException) {
                        throw ex as ServiceResultException;
                    }
                    throw new ServiceResultException(StatusCodes.BadInvalidArgument, ex.Message);
                }
            }

            /// <summary>
            /// Reads the actual Issuer CA cert of the group.
            /// Or a historical CA cert by thumbprint.
            /// </summary>
            /// <param name="thumbprint">optional, the thumbprint of the certificate.</param>
            /// <param name="nextPageLink"></param>
            /// <param name="pageSize"></param>
            /// <returns>The issuer certificate</returns>
            public async Task<X509CertificateCollectionModel> GetIssuerCACertificateAsync(
                string thumbprint, string nextPageLink, int? pageSize) {
                await LoadPublicAssetsAsync();
                var certificate = Certificate;
                if (thumbprint != null &&
                    !thumbprint.EqualsIgnoreCase(Certificate.Thumbprint)) {
                    try {
                        var (collection, nextLink) =
                            await _keyVaultServiceClient.ListCertificateVersionsAsync(
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
                var (result, nextLink) = await _keyVaultServiceClient.ListCertificateVersionsAsync(
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
            public async Task<X509CrlCollectionModel> GetIssuerCACrlAsync(string thumbprint, 
                string nextPageLink, int? pageSize) {
                await LoadPublicAssetsAsync();
                var crl = Crl;
                if (thumbprint != null && !thumbprint.EqualsIgnoreCase(Certificate.Thumbprint)) {
                    // TODO: implement paging (low priority, only when long chains are expected)
                    crl = await _keyVaultServiceClient.LoadIssuerCACrl(
                        _configuration.Id, thumbprint);
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
                var trustlist = await _keyVaultServiceClient.GetTrustListAsync(
                    _configuration.Id, pageSize, nextPageLink);
                return trustlist.ToServiceModel();
            }

            /// <summary>
            /// Load assets
            /// </summary>
            /// <returns></returns>
            private async Task LoadPublicAssetsAsync() {
                if (Certificate == null || _caCertSecretIdentifier == null ||
                    _caCertKeyIdentifier == null ||
                    TimeSpan.FromHours(1) < (DateTime.UtcNow - _lastUpdate)) {
                    await InitializeAsync();
                    _lastUpdate = DateTime.UtcNow;
                }
            }


            /// <summary>
            /// Get trimmed not before
            /// </summary>
            /// <returns></returns>
            private DateTime TrimmedNotBeforeDate() {
                var now = DateTime.UtcNow.AddDays(-1);
                return new DateTime(now.Year, now.Month, now.Day, 0, 0, 0, DateTimeKind.Utc);
            }

            private string _caCertSecretIdentifier;
            private string _caCertKeyIdentifier;
            private DateTime _lastUpdate;
            private readonly IKeyVaultServiceClient _keyVaultServiceClient;
            private readonly string _serviceHost;
            private readonly CertificateGroupInfoModel _configuration;
            private readonly SemaphoreSlim _semaphoreSlim = new SemaphoreSlim(1, 1);
        }

        private readonly IVaultConfig _config;
        private readonly IKeyVaultServiceClient _client;
        private readonly ILogger _logger;
        private readonly IGroupRegistry _registry;
    }
}
