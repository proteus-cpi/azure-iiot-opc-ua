// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace Microsoft.Azure.IIoT.OpcUa.Vault.Services.KeyVault.Services {
    using Microsoft.Azure.IIoT.OpcUa.Vault.Services.KeyVault;
    using Microsoft.Azure.IIoT.OpcUa.Vault.Models;
    using Microsoft.Azure.IIoT.Exceptions;
    using Opc.Ua;
    using Opc.Ua.Gds;
    using Opc.Ua.Gds.Server;
    using Org.BouncyCastle.Asn1.X509;
    using Org.BouncyCastle.Crypto;
    using Org.BouncyCastle.Crypto.Parameters;
    using Org.BouncyCastle.Math;
    using Org.BouncyCastle.Pkcs;
    using Org.BouncyCastle.Security;
    using Org.BouncyCastle.X509;
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;
    using System.Security.Cryptography;
    using System.Security.Cryptography.X509Certificates;
    using System.Threading;
    using System.Threading.Tasks;

    /// <summary>
    /// A certificate group where the Issuer CA cert and Crl are stored.
    /// </summary>
    public sealed class KeyVaultCertificateGroup : CertificateGroup {

        /// <summary>
        /// The latest Crl of this cert group
        /// </summary>
        public X509CRL Crl { get; set; }

        /// <summary>
        /// Certificate group configuration
        /// </summary>
        public CertificateGroupInfoModel CertificateGroupConfiguration { get; }

        /// <summary>
        /// Create group
        /// </summary>
        /// <param name="keyVaultServiceClient"></param>
        /// <param name="certificateGroupConfiguration"></param>
        /// <param name="serviceHost"></param>
        public KeyVaultCertificateGroup(IKeyVaultServiceClient keyVaultServiceClient,
            CertificateGroupInfoModel certificateGroupConfiguration,
            string serviceHost) :
            base(null, certificateGroupConfiguration.ToGdsServerModel()) {

            _keyVaultServiceClient = keyVaultServiceClient;
            _serviceHost = serviceHost ?? "localhost";
            CertificateGroupConfiguration = certificateGroupConfiguration;
            Certificate = null;
            Crl = null;
        }

        /// <inheritdoc/>
        public override async Task Init() {
            await _semaphoreSlim.WaitAsync();
            try {
                Utils.Trace(Utils.TraceMasks.Information, "InitializeCertificateGroup: {0}", m_subjectName);
                var result = await _keyVaultServiceClient.GetCertificateAsync(Configuration.Id)
                    .ConfigureAwait(false);
                Certificate = new X509Certificate2(result.Cer);
                if (Utils.CompareDistinguishedName(Certificate.Subject, Configuration.SubjectName)) {
                    _caCertSecretIdentifier = result.SecretIdentifier.Identifier;
                    _caCertKeyIdentifier = result.KeyIdentifier.Identifier;
                    Crl = await _keyVaultServiceClient.LoadIssuerCACrl(Configuration.Id, Certificate);
                }
                else {
                    throw new ResourceInvalidStateException(
                        "Key Vault certificate subject(" + Certificate.Subject +
                        ") does not match cert group subject " + Configuration.SubjectName);
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
                    null, null, Configuration.SubjectName, null, Configuration.CACertificateKeySize,
                    notBefore, Configuration.CACertificateLifetime, Configuration.CACertificateHashSize,
                    true, null, null)) {

                    // save only public key
                    Certificate = new X509Certificate2(caCert.RawData);

                    // initialize revocation list
                    Crl = CertificateFactory.RevokeCertificate(caCert, null, null);
                    if (Crl == null) {
                        return false;
                    }

                    // upload ca cert with private key
                    await _keyVaultServiceClient.ImportIssuerCACertificate(Configuration.Id,
                        new X509Certificate2Collection(caCert), true).ConfigureAwait(false);
                    await _keyVaultServiceClient.ImportIssuerCACrl(Configuration.Id,
                        Certificate, Crl).ConfigureAwait(false);
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
                var notAfter = notBefore.AddMonths(Configuration.CACertificateLifetime);

                // build distribution endpoint, if configured
                var crlDistributionPoint = BuildCrlDistributionPointUrl();

                // create new CA cert in HSM storage
                Certificate = await _keyVaultServiceClient.CreateCACertificateAsync(Configuration.Id,
                    Configuration.SubjectName, notBefore, notAfter, Configuration.CACertificateKeySize,
                    Configuration.CACertificateHashSize, true, crlDistributionPoint).ConfigureAwait(false);
                // update keys, ready back latest version
                var result = await _keyVaultServiceClient.GetCertificateAsync(
                    Configuration.Id).ConfigureAwait(false);
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
                    Configuration.CACertificateHashSize);

                // upload crl
                await _keyVaultServiceClient.ImportIssuerCACrl(
                    Configuration.Id, Certificate, Crl).ConfigureAwait(false);
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
        public override async Task<X509CRL> RevokeCertificateAsync(X509Certificate2 certificate) {
            await LoadPublicAssets().ConfigureAwait(false);
            var certificates = new X509Certificate2Collection { certificate };
            var caCertKeyInfoCollection = await _keyVaultServiceClient.ListCertificateVersionsKeyInfoAsync(
                Configuration.Id);
            var authorityKeyIdentifier = FindAuthorityKeyIdentifier(certificate);
            var now = DateTime.UtcNow;
            foreach (var caCertKeyInfo in caCertKeyInfoCollection) {
                var subjectKeyId = FindSubjectKeyIdentifierExtension(caCertKeyInfo.Certificate);
                if (Utils.CompareDistinguishedName(caCertKeyInfo.Certificate.Subject, certificate.Issuer) &&
                    authorityKeyIdentifier.SerialNumber.EqualsIgnoreCase(
                        caCertKeyInfo.Certificate.SerialNumber) &&
                    authorityKeyIdentifier.KeyId.EqualsIgnoreCase(
                        subjectKeyId.SubjectKeyIdentifier)
                    ) {
                    var crl = await _keyVaultServiceClient.LoadIssuerCACrl(
                        Configuration.Id, caCertKeyInfo.Certificate);
                    var crls = new List<X509CRL> { crl };
                    var newCrl = CertUtils.RevokeCertificate(caCertKeyInfo.Certificate, crls,
                        certificates, now, DateTime.MinValue, new KeyVaultSignatureGenerator(
                            _keyVaultServiceClient, caCertKeyInfo.KeyIdentifier, caCertKeyInfo.Certificate),
                        Configuration.CACertificateHashSize);
                    await _keyVaultServiceClient.ImportIssuerCACrl(
                        Configuration.Id, caCertKeyInfo.Certificate, newCrl).ConfigureAwait(false);
                    Crl = await _keyVaultServiceClient.LoadIssuerCACrl(Configuration.Id, Certificate);
                    return newCrl;
                }
            }
            return null;
        }

        /// <summary>
        /// Revokes a certificate collection.
        /// Finds for each the matching CA cert version and updates Crl.
        /// </summary>
        /// <returns></returns>
        public async Task<X509Certificate2Collection> RevokeCertificatesAsync(
            X509Certificate2Collection certificates) {
            var remainingCertificates = new X509Certificate2Collection(certificates);
            await LoadPublicAssets().ConfigureAwait(false);
            var caCertKeyInfoCollection = await _keyVaultServiceClient.ListCertificateVersionsKeyInfoAsync(
                Configuration.Id);
            var now = DateTime.UtcNow;
            foreach (var caCertKeyInfo in caCertKeyInfoCollection) {
                if (remainingCertificates.Count == 0) {
                    break;
                }
                var caRevokeCollection = new X509Certificate2Collection();
                foreach (var cert in remainingCertificates) {
                    var authorityKeyIdentifier = FindAuthorityKeyIdentifier(cert);
                    var subjectKeyId = FindSubjectKeyIdentifierExtension(caCertKeyInfo.Certificate);
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
                var crl = await _keyVaultServiceClient.LoadIssuerCACrl(Configuration.Id, caCertKeyInfo.Certificate);
                var crls = new List<X509CRL> { crl };
                var newCrl = CertUtils.RevokeCertificate(caCertKeyInfo.Certificate, crls,
                    caRevokeCollection, now, DateTime.MinValue, new KeyVaultSignatureGenerator(
                        _keyVaultServiceClient, caCertKeyInfo.KeyIdentifier, caCertKeyInfo.Certificate),
                    Configuration.CACertificateHashSize);
                await _keyVaultServiceClient.ImportIssuerCACrl(
                    Configuration.Id, caCertKeyInfo.Certificate, newCrl).ConfigureAwait(false);

                foreach (var cert in caRevokeCollection) {
                    remainingCertificates.Remove(cert);
                }
            }
            Crl = await _keyVaultServiceClient.LoadIssuerCACrl(Configuration.Id, Certificate);
            return remainingCertificates;
        }

        /// <summary>
        /// Creates a new key pair as KeyVault certificate and signs it with KeyVault.
        /// </summary>
        /// <returns></returns>
        public async Task<X509Certificate2KeyPair> NewKeyPairRequestKeyVaultCertAsync(
            ApplicationRecordDataType application, string subjectName, string[] domainNames,
            string privateKeyFormat, string privateKeyPassword) {

            await LoadPublicAssets().ConfigureAwait(false);
            var notBefore = TrimmedNotBeforeDate();
            var notAfter = notBefore.AddMonths(Configuration.DefaultCertificateLifetime);

            var authorityInformationAccess = BuildAuthorityInformationAccessUrl();
            // create new cert with KeyVault
            using (var signedCertWithPrivateKey = await _keyVaultServiceClient.CreateSignedKeyPairCertAsync(
                Configuration.Id, Certificate, application.ApplicationUri,
                application.ApplicationNames.Count > 0 ?
                    application.ApplicationNames[0].Text : "ApplicationName",
                subjectName, domainNames, notBefore, notAfter, Configuration.DefaultCertificateKeySize,
                Configuration.DefaultCertificateHashSize, new KeyVaultSignatureGenerator(
                    _keyVaultServiceClient, _caCertKeyIdentifier, Certificate),
                authorityInformationAccess).ConfigureAwait(false)) {
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
        public override async Task<X509Certificate2KeyPair> NewKeyPairRequestAsync(
            ApplicationRecordDataType application, string subjectName, string[] domainNames,
            string privateKeyFormat, string privateKeyPassword) {
            if (!privateKeyFormat.Equals("PFX", StringComparison.OrdinalIgnoreCase) &&
                !privateKeyFormat.Equals("PEM", StringComparison.OrdinalIgnoreCase)) {
                throw new ServiceResultException(StatusCodes.BadInvalidArgument,
                    "Invalid private key format");
            }
            var notBefore = DateTime.UtcNow.AddDays(-1);
            // create public/private key pair
            using (var keyPair = RSA.Create(Configuration.DefaultCertificateKeySize)) {
                await LoadPublicAssets().ConfigureAwait(false);
                var authorityInformationAccess = BuildAuthorityInformationAccessUrl();

                // sign public key with KeyVault
                var signedCert = await CertUtils.CreateSignedCertificate(
                    application.ApplicationUri, application.ApplicationNames.Count > 0 ?
                        application.ApplicationNames[0].Text : "ApplicationName",
                    subjectName, domainNames, Configuration.DefaultCertificateKeySize,
                    notBefore, notBefore.AddMonths(Configuration.DefaultCertificateLifetime),
                    Configuration.DefaultCertificateHashSize, Certificate, keyPair,
                    new KeyVaultSignatureGenerator(
                        _keyVaultServiceClient, _caCertKeyIdentifier, Certificate),
                    false, authorityInformationAccess);
                // Create a PEM or PFX
                using (var signedCertWithPrivateKey = CreateCertificateWithPrivateKey(
                    signedCert, keyPair)) {
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
                Configuration.Id, requestId, privateKey, privateKeyFormat, ct);
        }

        /// <summary>
        /// Load the private key of a cert request from Key Vault secret.
        /// </summary>
        public async Task<byte[]> LoadPrivateKeyAsync(string requestId,
            string privateKeyFormat, CancellationToken ct = default) {
            return await _keyVaultServiceClient.LoadKeySecretAsync(
                Configuration.Id, requestId,
                privateKeyFormat, ct);
        }

        /// <summary>
        /// Accept the private key of a cert request from Key Vault secret.
        /// </summary>
        public async Task AcceptPrivateKeyAsync(string requestId,
            CancellationToken ct = default) {
            await _keyVaultServiceClient.InvalidateKeySecretAsync(
                Configuration.Id, requestId, ct);
        }

        /// <summary>
        /// Delete the private key of a cert request from Key Vault secret.
        /// </summary>
        public async Task DeletePrivateKeyAsync(string requestId,
            CancellationToken ct = default) {
            await _keyVaultServiceClient.DeleteKeySecretAsync(
                Configuration.Id, requestId, ct);
        }

        /// <inheritdoc/>
        public override async Task<X509Certificate2> SigningRequestAsync(
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
                var altNameExtension = GetAltNameExtensionFromCSRInfo(info);
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

                var authorityInformationAccess = BuildAuthorityInformationAccessUrl();
                var notBefore = DateTime.UtcNow.AddDays(-1);
                await LoadPublicAssets().ConfigureAwait(false);
                var signingCert = Certificate;
                {
                    var publicKey = CertUtils.GetRSAPublicKey(
                        info.SubjectPublicKeyInfo);
                    return await CertUtils.CreateSignedCertificate(application.ApplicationUri,
                        application.ApplicationNames.Count > 0 ?
                            application.ApplicationNames[0].Text : "ApplicationName",
                        info.Subject.ToString(), domainNames,
                        Configuration.DefaultCertificateKeySize, notBefore,
                        notBefore.AddMonths(Configuration.DefaultCertificateLifetime),
                        Configuration.DefaultCertificateHashSize, signingCert,
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
        /// <returns>The issuer certificate</returns>
        public async Task<X509Certificate2> GetIssuerCACertificateAsync(string thumbprint) {
            await LoadPublicAssets().ConfigureAwait(false);
            if (thumbprint == null ||
                thumbprint.Equals(Certificate.Thumbprint, StringComparison.OrdinalIgnoreCase)) {
                return Certificate;
            }
            else {
                try {
                    var (collection, nextPageLink) =
                        await _keyVaultServiceClient.ListCertificateVersionsAsync(
                            Configuration.Id, thumbprint, pageSize: 1);
                    if (collection.Count == 1) {
                        return collection[0];
                    }
                }
#pragma warning disable RECS0022 // A catch clause that catches System.Exception and has an empty body
                catch {
#pragma warning restore RECS0022 // A catch clause that catches System.Exception and has an empty body
                }
                throw new ResourceNotFoundException("A Certificate for this thumbprint doesn't exist.");
            }
        }

        /// <summary>
        /// Get the actual Crl of a certificate group.
        /// Or the Crl of a historical Issuer CA cert by thumbprint.
        /// </summary>
        /// <param name="thumbprint">optional, the thumbprint of the certificate.</param>
        /// <returns></returns>
        public async Task<X509CRL> GetIssuerCACrlAsync(string thumbprint) {
            await LoadPublicAssets().ConfigureAwait(false);
            if (thumbprint == null ||
                thumbprint.Equals(Certificate.Thumbprint, StringComparison.OrdinalIgnoreCase)) {
                return Crl;
            }
            return await _keyVaultServiceClient.LoadIssuerCACrl(Configuration.Id, thumbprint);
        }

        /// <inheritdoc/>
        public override Task<X509Certificate2> LoadSigningKeyAsync(
            X509Certificate2 signingCertificate, string signingKeyPassword) {
#if LOADPRIVATEKEY
            await LoadPublicAssets();
            return await _keyVaultServiceClient.LoadSigningCertificateAsync(
                _caCertSecretIdentifier,
                Certificate);
#else
            throw new NotSupportedException(
                "Loading a private key from Key Vault is not supported.");
#endif
        }

        /// <summary>
        /// Load assets
        /// </summary>
        /// <returns></returns>
        private async Task LoadPublicAssets() {
            if (Certificate == null || _caCertSecretIdentifier == null ||
                _caCertKeyIdentifier == null ||
                TimeSpan.FromHours(1) < (DateTime.UtcNow - _lastUpdate)) {
                await Init();
                _lastUpdate = DateTime.UtcNow;
            }
        }

        /// <summary>
        /// Create default configuration
        /// </summary>
        /// <param name="id"></param>
        /// <param name="subject"></param>
        /// <param name="certType"></param>
        /// <returns></returns>
        public static CertificateGroupInfoModel DefaultConfiguration(
            string id, string subject, CertificateType certType) {
            var config = new CertificateGroupInfoModel {
                Id = id ?? "Default",
                SubjectName = subject ?? "CN=Azure Industrial IoT CA, O=Microsoft Corp.",
                CertificateType = certType,
                DefaultCertificateLifetime = 24,
                DefaultCertificateHashSize = 256,
                DefaultCertificateKeySize = 2048,
                IssuerCACertificateLifetime = 60,
                IssuerCACertificateHashSize = 256,
                IssuerCACertificateKeySize = 2048,
                IssuerCACrlDistributionPoint = "http://%servicehost%/certs/crl/%serial%/%group%.crl",
                IssuerCAAuthorityInformationAccess = "http://%servicehost%/certs/issuer/%serial%/%group%.cer"
            };
            config.ValidateConfiguration();
            return config;
        }

        /// <summary>
        /// Find auth key
        /// </summary>
        /// <param name="certificate"></param>
        /// <returns></returns>
        private static X509AuthorityKeyIdentifierExtension FindAuthorityKeyIdentifier(X509Certificate2 certificate) {
            foreach (var extension in certificate.Extensions) {
                switch (extension.Oid.Value) {
                    case X509AuthorityKeyIdentifierExtension.AuthorityKeyIdentifierOid:
                    case X509AuthorityKeyIdentifierExtension.AuthorityKeyIdentifier2Oid:
                        return new X509AuthorityKeyIdentifierExtension(extension, extension.Critical);

                }
            }
            return null;
        }

        /// <summary>
        /// Find subject key in certificate
        /// </summary>
        /// <param name="certificate"></param>
        /// <returns></returns>
        private static X509SubjectKeyIdentifierExtension FindSubjectKeyIdentifierExtension(
            X509Certificate2 certificate) {
            foreach (var extension in certificate.Extensions) {
                if (extension is X509SubjectKeyIdentifierExtension subjectKeyExtension) {
                    return subjectKeyExtension;
                }
            }
            return null;
        }

        /// <summary>
        /// Create a X509Certificate2 with a private key by combining
        /// the new certificate with a private key from an RSA key.
        /// </summary>
        public static X509Certificate2 CreateCertificateWithPrivateKey(
            X509Certificate2 certificate, RSA privatekey) {
            using (var cfrg = new CertificateFactoryRandomGenerator()) {
                var random = new SecureRandom(cfrg);
                var x509 = new X509CertificateParser().ReadCertificate(certificate.RawData);
                return CreateCertificateWithPrivateKey(x509, certificate.FriendlyName,
                    GetPrivateKeyParameter(privatekey), random);
            }
        }

        /// <summary>
        /// Create a X509Certificate2 with a private key by combining
        /// a bouncy castle X509Certificate and private key parameters.
        /// </summary>
        private static X509Certificate2 CreateCertificateWithPrivateKey(
            Org.BouncyCastle.X509.X509Certificate certificate, string friendlyName,
            AsymmetricKeyParameter privateKey, SecureRandom random) {
            // create pkcs12 store for cert and private key
            using (var pfxData = new MemoryStream()) {
                var builder = new Pkcs12StoreBuilder();
                builder.SetUseDerEncoding(true);
                var pkcsStore = builder.Build();
                var chain = new X509CertificateEntry[1];
                var passcode = Guid.NewGuid().ToString();
                chain[0] = new X509CertificateEntry(certificate);
                if (string.IsNullOrEmpty(friendlyName)) {
                    friendlyName = GetCertificateCommonName(certificate);
                }
                pkcsStore.SetKeyEntry(friendlyName, new AsymmetricKeyEntry(privateKey), chain);
                pkcsStore.Save(pfxData, passcode.ToCharArray(), random);
                // merge into X509Certificate2
                return CertificateFactory.CreateCertificateFromPKCS12(pfxData.ToArray(), passcode);
            }
        }

        /// <summary>
        /// Read the Common Name from a certificate.
        /// </summary>
        private static string GetCertificateCommonName(
            Org.BouncyCastle.X509.X509Certificate certificate) {
            var subjectDN = certificate.SubjectDN.GetValueList(X509Name.CN);
            if (subjectDN.Count > 0) {
                return subjectDN[0].ToString();
            }
            return string.Empty;
        }

        /// <summary>
        /// Get private key parameters from a RSA key.
        /// The private key must be exportable.
        /// </summary>
        private static RsaPrivateCrtKeyParameters GetPrivateKeyParameter(RSA rsaKey) {
            var rsaParams = rsaKey.ExportParameters(true);
            var keyParams = new RsaPrivateCrtKeyParameters(
                new BigInteger(1, rsaParams.Modulus),
                new BigInteger(1, rsaParams.Exponent),
                new BigInteger(1, rsaParams.D),
                new BigInteger(1, rsaParams.P),
                new BigInteger(1, rsaParams.Q),
                new BigInteger(1, rsaParams.DP),
                new BigInteger(1, rsaParams.DQ),
                new BigInteger(1, rsaParams.InverseQ));
            return keyParams;
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
        /// Build crl distribution point url
        /// </summary>
        /// <returns></returns>
        private string BuildCrlDistributionPointUrl() {
            if (!string.IsNullOrWhiteSpace(CertificateGroupConfiguration.IssuerCACrlDistributionPoint)) {
                return PatchEndpointUrl(CertificateGroupConfiguration.IssuerCACrlDistributionPoint);
            }
            return null;
        }

        /// <summary>
        /// Build auth url
        /// </summary>
        /// <returns></returns>
        private string BuildAuthorityInformationAccessUrl() {
            if (!string.IsNullOrWhiteSpace(CertificateGroupConfiguration.IssuerCAAuthorityInformationAccess)) {
                return PatchEndpointUrl(CertificateGroupConfiguration.IssuerCAAuthorityInformationAccess);
            }
            return null;
        }

        /// <summary>
        /// Patch endpoint url
        /// </summary>
        /// <param name="endPointUrl"></param>
        /// <returns></returns>
        private string PatchEndpointUrl(string endPointUrl) {
            var patchedServiceHost = endPointUrl.Replace("%servicehost%", _serviceHost);
            return patchedServiceHost.Replace("%group%", Configuration.Id.ToLower());
        }

        private readonly IKeyVaultServiceClient _keyVaultServiceClient;
        private readonly string _serviceHost;
        private string _caCertSecretIdentifier;
        private string _caCertKeyIdentifier;
        private DateTime _lastUpdate;
        private readonly SemaphoreSlim _semaphoreSlim = new SemaphoreSlim(1, 1);
    }
}
