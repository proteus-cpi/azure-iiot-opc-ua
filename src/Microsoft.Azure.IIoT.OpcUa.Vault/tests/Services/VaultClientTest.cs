// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace Microsoft.Azure.IIoT.OpcUa.Vault.Tests {
    using Microsoft.Azure.IIoT.Exceptions;
    using Microsoft.Azure.IIoT.OpcUa.Vault.Models;
    using Microsoft.Azure.IIoT.OpcUa.Vault.Services;
    using Microsoft.Azure.IIoT.OpcUa.Vault.Tests.Helpers;
    using Microsoft.Azure.KeyVault.Models;
    using Serilog;
    using System;
    using System.Linq;
    using System.Security.Cryptography.X509Certificates;
    using System.Threading.Tasks;
    using TestCaseOrdering;
    using Xunit;
    using Xunit.Abstractions;

    [TestCaseOrderer("TestCaseOrdering.PriorityOrderer", "Microsoft.Azure.IIoT.OpcUa.Vault.Tests")]
    public class VaultClientTest : IClassFixture<VaultClientTestFixture> {

        public VaultClientTest(VaultClientTestFixture fixture, ITestOutputHelper log) {
            _logger = SerilogTestLogger.Create<VaultClientTest>(log);
            _fixture = fixture;
            _vaultClient = _fixture.VaultClient;
            _fixture.SkipOnInvalidConfiguration();
        }

        /// <summary>
        /// Initialize the cert group once and for all tests.
        /// </summary>
        [SkippableFact, Trait(Constants.Type, Constants.UnitTest), TestPriority(1)]
        public async Task KeyVaultInitAsync() {
            _logger.Information("Initializing KeyVault");
            await _vaultClient.InitializeAsync();
            _fixture.KeyVaultInitOk = true;
        }

        /// <summary>
        /// Purge the KeyVault from all certificates and secrets touched by this test.
        /// </summary>
        [SkippableFact, Trait(Constants.Type, Constants.UnitTest), TestPriority(100)]
        public async Task KeyVaultPurgeCACertificateAsync() {
            Skip.If(!_fixture.KeyVaultInitOk);
            await _vaultClient.PurgeAsync(null, _fixture.GroupId);
        }

        /// <summary>
        /// Create a new IssuerCA Certificate with CRL according to the group configuration.
        /// </summary>
        [SkippableFact, Trait(Constants.Type, Constants.UnitTest), TestPriority(200)]
        public async Task KeyVaultCreateCACertificateAsync() {
            Skip.If(!_fixture.KeyVaultInitOk);
            var groups = await _vaultClient.GetGroupIdsAsync();
            foreach (var group in groups) {
                var result = await _vaultClient.CreateIssuerCACertificateAsync(group);
                Assert.NotNull(result);
                Assert.False(result.ToStackModel().HasPrivateKey);
                Assert.True(Opc.Ua.Utils.CompareDistinguishedName(result.ToStackModel().Issuer, result.Subject));
                var basicConstraints = X509TestUtils.FindBasicConstraintsExtension(result.ToStackModel());
                Assert.NotNull(basicConstraints);
                Assert.True(basicConstraints.CertificateAuthority);
                Assert.True(basicConstraints.Critical);
                var subjectKeyId = result.ToStackModel().Extensions.OfType<X509SubjectKeyIdentifierExtension>().Single();
                Assert.False(subjectKeyId.Critical);
                var authorityKeyIdentifier = X509TestUtils.FindAuthorityKeyIdentifier(result.ToStackModel());
                Assert.NotNull(authorityKeyIdentifier);
                Assert.False(authorityKeyIdentifier.Critical);
                Assert.Equal(authorityKeyIdentifier.SerialNumber, result.SerialNumber, true);
                Assert.Equal(authorityKeyIdentifier.KeyId, subjectKeyId.SubjectKeyIdentifier, true);
            }
        }

        /// <summary>
        /// Read the list of groud ids supported in the configuration.
        /// </summary>
        [SkippableFact, Trait(Constants.Type, Constants.UnitTest), TestPriority(400)]
        public async Task KeyVaultListOfCertGroups() {
            Skip.If(!_fixture.KeyVaultInitOk);
            var groups = await _vaultClient.GetGroupIdsAsync();
            Assert.NotNull(groups);
            Assert.NotEmpty(groups);
        }

        /// <summary>
        /// Read all certificate group configurations.
        /// </summary>
        [SkippableFact, Trait(Constants.Type, Constants.UnitTest), TestPriority(400)]
        public async Task KeyVaultGroupConfigurationCollection() {
            Skip.If(!_fixture.KeyVaultInitOk);
            var groupCollection = await _vaultClient.ListGroupConfigurationsAsync();
            Assert.NotNull(groupCollection);
            Assert.NotEmpty(groupCollection.Groups);
            foreach (var groupConfig in groupCollection.Groups) {
                Assert.NotNull(groupConfig.Id);
                Assert.NotEmpty(groupConfig.Id);
                Assert.NotNull(groupConfig.SubjectName);
                Assert.NotEmpty(groupConfig.SubjectName);
            }
        }

        /// <summary>
        /// Read the Issuer CA Certificate and CRL Chain for each group.
        /// </summary>
        /// <returns></returns>
        [SkippableFact, Trait(Constants.Type, Constants.UnitTest), TestPriority(400)]
        public async Task KeyVaultGetCertificateAsync() {
            Skip.If(!_fixture.KeyVaultInitOk);
            var groups = await _vaultClient.GetGroupIdsAsync();
            foreach (var group in groups) {
                var caChain = await _vaultClient.GetIssuerCACertificateChainAsync(group);
                Assert.NotNull(caChain);
                Assert.NotNull(caChain.Chain);
                Assert.True(caChain.Chain.Count >= 1);
                foreach (var caCert in caChain.Chain) {
                    Assert.False(caCert.ToStackModel().HasPrivateKey);
                }
                var crlChain = await _vaultClient.GetIssuerCACrlChainAsync(group);
                Assert.NotNull(crlChain);
                Assert.True(crlChain.Chain.Count >= 1);
                for (var i = 0; i < caChain.Chain.Count; i++) {
                    crlChain.Chain[i].ToStackModel().VerifySignature(caChain.Chain[i].ToStackModel(), true);
                    Assert.True(Opc.Ua.Utils.CompareDistinguishedName(
                        crlChain.Chain[i].Issuer, caChain.Chain[i].ToStackModel().Issuer));
                }
            }
        }

        /// <summary>
        /// Create a new key pair with a issuer signed certificate in KeyVault.
        /// </summary>
        [SkippableFact, Trait(Constants.Type, Constants.UnitTest), TestPriority(500)]
        public async Task<X509CertificateCollection> KeyVaultNewKeyPairRequestAsync() {
            Skip.If(!_fixture.KeyVaultInitOk);
            var certCollection = new X509CertificateCollection();
            var groups = await _vaultClient.GetGroupIdsAsync();
            foreach (var group in groups) {
                var randomApp = _fixture.RandomGenerator.RandomApplicationTestData();
                var requestId = Guid.NewGuid();
                var newKeyPair = await _vaultClient.NewKeyPairRequestAsync(
                    group,
                    requestId.ToString(),
                    randomApp.ApplicationRecord.ApplicationUri,
                    randomApp.Subject,
                    randomApp.DomainNames.ToArray(),
                    randomApp.PrivateKeyFormat,
                    randomApp.PrivateKeyPassword);
                Assert.NotNull(newKeyPair);
                Assert.False(newKeyPair.Certificate.ToStackModel().HasPrivateKey);
                Assert.True(Opc.Ua.Utils.CompareDistinguishedName(randomApp.Subject, newKeyPair.Certificate.Subject));
                Assert.False(Opc.Ua.Utils.CompareDistinguishedName(
                    newKeyPair.Certificate.ToStackModel().Issuer, newKeyPair.Certificate.Subject));
                var issuerCerts = await _vaultClient.GetIssuerCACertificateChainAsync(group);
                Assert.NotNull(issuerCerts);
                Assert.True(issuerCerts.Chain.Count >= 1);

                X509TestUtils.VerifyApplicationCertIntegrity(
                    newKeyPair.Certificate.ToStackModel(),
                    newKeyPair.PrivateKey,
                    randomApp.PrivateKeyPassword,
                    randomApp.PrivateKeyFormat,
                    issuerCerts.ToStackModel()
                    );
                certCollection.Add(newKeyPair.Certificate.ToStackModel());

                // disable and delete private key from KeyVault (requires set/delete rights)
                await _vaultClient.AcceptPrivateKeyAsync(group, requestId.ToString());
                await _vaultClient.DeletePrivateKeyAsync(group, requestId.ToString());
            }
            return certCollection;
        }

        /// <summary>
        /// Create a new issuer signed certificate from a CSR in KeyVault.
        /// Validate the signed certificate aginst the issuer CA chain.
        /// </summary>
        [SkippableFact, Trait(Constants.Type, Constants.UnitTest), TestPriority(500)]
        public async Task<X509CertificateCollection> KeyVaultSigningRequestAsync() {
            Skip.If(!_fixture.KeyVaultInitOk);
            var certCollection = new X509CertificateCollection();
            var groups = await _vaultClient.GetGroupIdsAsync();
            foreach (var group in groups) {
                var certificateGroupConfiguration = await _vaultClient.GetGroupConfigurationAsync(group);
                var randomApp = _fixture.RandomGenerator.RandomApplicationTestData();
                var csrCertificate = CertificateFactory.CreateCertificate(
                    null, null, null,
                    randomApp.ApplicationRecord.ApplicationUri,
                    null,
                    randomApp.Subject,
                    randomApp.DomainNames.ToArray(),
                    certificateGroupConfiguration.DefaultCertificateKeySize,
                    DateTime.UtcNow.AddDays(-10),
                    certificateGroupConfiguration.DefaultCertificateLifetime,
                    certificateGroupConfiguration.DefaultCertificateHashSize
                    );
                var certificateRequest = CertificateFactory.CreateSigningRequest(csrCertificate, randomApp.DomainNames);

                var newCert = await _vaultClient.SigningRequestAsync(
                    group,
                    randomApp.ApplicationRecord.ApplicationUri,
                    certificateRequest);
                // get issuer cert used for signing
                var issuerCerts = await _vaultClient.GetIssuerCACertificateChainAsync(group);
#if WRITECERT
                // save cert for debugging
                using (var store = Opc.Ua.CertificateStoreIdentifier.CreateStore(Opc.Ua.CertificateStoreType.Directory))
                {
                    Assert.NotNull(store);
                    store.Open("d:\\unittest");
                    await store.Add(newCert.ToStackModel());
                    foreach (var cert in issuerCerts.ToStackModel()) await store.Add(cert);
                }
#endif
                Assert.NotNull(issuerCerts);
                Assert.True(issuerCerts.Chain.Count >= 1);
                X509TestUtils.VerifySignedApplicationCert(randomApp, newCert.ToStackModel(), issuerCerts.ToStackModel());
                certCollection.Add(newCert.ToStackModel());
            }
            return certCollection;
        }

        /// <summary>
        /// Create a new key pair with a issuer signed certificate in KeyVault.
        /// Validate the signed certificate, then revoke it. Then verify revocation.
        /// </summary>
        [SkippableFact, Trait(Constants.Type, Constants.UnitTest), TestPriority(600)]
        public async Task KeyVaultNewKeyPairAndRevokeCertificateAsync() {
            Skip.If(!_fixture.KeyVaultInitOk);
            var groups = await _vaultClient.GetGroupIdsAsync();
            foreach (var group in groups) {
                var randomApp = _fixture.RandomGenerator.RandomApplicationTestData();
                var requestId = Guid.NewGuid();
                var newCert = await _vaultClient.NewKeyPairRequestAsync(
                    group,
                    requestId.ToString(),
                    randomApp.ApplicationRecord.ApplicationUri,
                    randomApp.Subject,
                    randomApp.DomainNames.ToArray(),
                    randomApp.PrivateKeyFormat,
                    randomApp.PrivateKeyPassword
                    );
                Assert.NotNull(newCert);
                Assert.False(newCert.Certificate.ToStackModel().HasPrivateKey);
                Assert.True(Opc.Ua.Utils.CompareDistinguishedName(randomApp.Subject, newCert.Certificate.Subject));
                Assert.False(Opc.Ua.Utils.CompareDistinguishedName(
                    newCert.Certificate.ToStackModel().Issuer, newCert.Certificate.Subject));
                var cert = new X509Certificate2(newCert.Certificate.ToRawData());
                var crl = await _vaultClient.RevokeCertificateAsync(group, cert.ToServiceModel());
                Assert.NotNull(crl);
                var caChain = await _vaultClient.GetIssuerCACertificateChainAsync(group);
                Assert.NotNull(caChain);
                var caCert = caChain.Chain[0];
                Assert.False(caCert.ToStackModel().HasPrivateKey);
                crl.ToStackModel().VerifySignature(caCert.ToStackModel(), true);
                Assert.True(Opc.Ua.Utils.CompareDistinguishedName(crl.Issuer, caCert.ToStackModel().Issuer));
                // disable and delete private key from KeyVault (requires set/delete rights)
                await _vaultClient.AcceptPrivateKeyAsync(group, requestId.ToString());
                await _vaultClient.DeletePrivateKeyAsync(group, requestId.ToString());
            }
        }

        /// <summary>
        /// Create a new key pair with a issuer signed certificate in KeyVault.
        /// Load the private key and validate the public/private key.
        /// Accept and delete the private. Verify the private kay is deleted.
        /// </summary>
        /// <returns></returns>
        [SkippableFact, Trait(Constants.Type, Constants.UnitTest), TestPriority(600)]
        public async Task KeyVaultNewKeyPairLoadThenDeletePrivateKeyAsync() {
            Skip.If(!_fixture.KeyVaultInitOk);
            var groups = await _vaultClient.GetGroupIdsAsync();
            foreach (var group in groups) {
                var randomApp = _fixture.RandomGenerator.RandomApplicationTestData();
                var requestId = Guid.NewGuid();
                var newKeyPair = await _vaultClient.NewKeyPairRequestAsync(
                    group,
                    requestId.ToString(),
                    randomApp.ApplicationRecord.ApplicationUri,
                    randomApp.Subject,
                    randomApp.DomainNames.ToArray(),
                    randomApp.PrivateKeyFormat,
                    randomApp.PrivateKeyPassword
                    );
                Assert.NotNull(newKeyPair);
                Assert.False(newKeyPair.Certificate.ToStackModel().HasPrivateKey);
                Assert.True(Opc.Ua.Utils.CompareDistinguishedName(randomApp.Subject, newKeyPair.Certificate.Subject));
                Assert.False(Opc.Ua.Utils.CompareDistinguishedName(
                    newKeyPair.Certificate.ToStackModel().Issuer, newKeyPair.Certificate.Subject));

                var issuerCerts = await _vaultClient.GetIssuerCACertificateChainAsync(group);
                Assert.NotNull(issuerCerts);
                Assert.True(issuerCerts.Chain.Count >= 1);

                X509TestUtils.VerifyApplicationCertIntegrity(
                    newKeyPair.Certificate.ToStackModel(),
                    newKeyPair.PrivateKey,
                    randomApp.PrivateKeyPassword,
                    randomApp.PrivateKeyFormat,
                    issuerCerts.ToStackModel()
                    );

                // test to load the key from KeyVault
                var privateKey = await _vaultClient.LoadPrivateKeyAsync(group, requestId.ToString(), randomApp.PrivateKeyFormat);
                X509Certificate2 privateKeyX509;
                if (randomApp.PrivateKeyFormat == "PFX") {
                    privateKeyX509 = CertificateFactory.CreateCertificateFromPKCS12(privateKey, randomApp.PrivateKeyPassword);
                }
                else {
                    privateKeyX509 = CertificateFactory.CreateCertificateWithPEMPrivateKey(
                        newKeyPair.Certificate.ToStackModel(), privateKey, randomApp.PrivateKeyPassword);
                }
                Assert.True(privateKeyX509.HasPrivateKey);

                X509TestUtils.VerifyApplicationCertIntegrity(
                    newKeyPair.Certificate.ToStackModel(),
                    privateKey,
                    randomApp.PrivateKeyPassword,
                    randomApp.PrivateKeyFormat,
                    issuerCerts.ToStackModel()
                    );

                await _vaultClient.AcceptPrivateKeyAsync(group, requestId.ToString());
                await Assert.ThrowsAsync<KeyVaultErrorException>(async () => privateKey =
                await _vaultClient.LoadPrivateKeyAsync(group, requestId.ToString(), randomApp.PrivateKeyFormat));
                await _vaultClient.AcceptPrivateKeyAsync(group, requestId.ToString());
                await _vaultClient.DeletePrivateKeyAsync(group, requestId.ToString());
                await Assert.ThrowsAsync<KeyVaultErrorException>(() => _vaultClient.DeletePrivateKeyAsync(group, requestId.ToString()));
                await Assert.ThrowsAsync<KeyVaultErrorException>(async () => privateKey =
                await _vaultClient.LoadPrivateKeyAsync(group, requestId.ToString(), randomApp.PrivateKeyFormat));
            }
        }

        /// <summary>
        /// Get the certificate versions for every group, try paging..
        /// </summary>
        [SkippableFact, Trait(Constants.Type, Constants.UnitTest), TestPriority(3000)]
        public async Task GetCertificateVersionsAsync() {
            Skip.If(!_fixture.KeyVaultInitOk);
            var groups = await _vaultClient.GetGroupIdsAsync();
            foreach (var group in groups) {
                // read all certs
                var certCollection = await _vaultClient.GetIssuerCACertificateVersionsAsync(group, true, null, 2);
                while (certCollection.NextPageLink != null) {
                    var next = await _vaultClient.GetIssuerCACertificateVersionsAsync(group, true, certCollection.NextPageLink, 2);
                    certCollection.AddRange(next);
                    certCollection.NextPageLink = next.NextPageLink;
                }

                // read all matching cert and crl by thumbprint
                var chainId = await _vaultClient.GetIssuerCACertificateChainAsync(group);
                Assert.NotNull(chainId);
                Assert.True(chainId.Chain.Count >= 1);
                var crlId = await _vaultClient.GetIssuerCACrlChainAsync(group);
                Assert.NotNull(chainId);
                Assert.True(chainId.Chain.Count >= 1);
                foreach (var cert in certCollection.Chain) {
                    var certChain = await _vaultClient.GetIssuerCACertificateChainAsync(group, cert.Thumbprint);
                    Assert.NotNull(certChain);
                    Assert.True(certChain.Chain.Count >= 1);
                    Assert.Equal(cert.Thumbprint, certChain.Chain[0].Thumbprint);

                    var crlChain = await _vaultClient.GetIssuerCACrlChainAsync(group, cert.Thumbprint);
                    Assert.NotNull(crlChain);
                    Assert.True(crlChain.Chain.Count >= 1);
                    crlChain.Chain[0].ToStackModel().VerifySignature(cert.ToStackModel(), true);
                    crlChain.Chain[0].ToStackModel().VerifySignature(certChain.Chain[0].ToStackModel(), true);

                    // invalid parameter test
                    // invalid parameter test
                    await Assert.ThrowsAsync<ResourceNotFoundException>(() => _vaultClient.GetIssuerCACrlChainAsync(group, cert.Thumbprint + "a"));
                    await Assert.ThrowsAsync<ResourceNotFoundException>(() => _vaultClient.GetIssuerCACrlChainAsync("abc", cert.Thumbprint));
                }

                // invalid parameters
                await Assert.ThrowsAsync<ResourceNotFoundException>(() => _vaultClient.GetIssuerCACrlChainAsync(group, "abcd"));
                await Assert.ThrowsAsync<ResourceNotFoundException>(() => _vaultClient.GetIssuerCACertificateChainAsync("abc"));
                await Assert.ThrowsAsync<ResourceNotFoundException>(() => _vaultClient.GetIssuerCACrlChainAsync("abc"));
            }
        }

        /// <summary>
        /// Read the trust list for every group.
        /// </summary>
        [SkippableFact, Trait(Constants.Type, Constants.UnitTest), TestPriority(3000)]
        public async Task GetTrustListAsync() {
            Skip.If(!_fixture.KeyVaultInitOk);
            var groups = await _vaultClient.GetGroupIdsAsync();
            foreach (var group in groups) {
                var trustList = await _vaultClient.GetTrustListAsync(group, null, 2);
                var nextPageLink = trustList.NextPageLink;
                while (nextPageLink != null) {
                    var nextTrustList = await _vaultClient.GetTrustListAsync(group, nextPageLink, 2);
                    trustList.AddRange(nextTrustList);
                    nextPageLink = nextTrustList.NextPageLink;
                }
                var validator = X509TestUtils.CreateValidatorAsync(trustList);
            }
        }

        /// <summary>
        /// Create new CA, create a few signed Certs and key pairs.
        /// Repeat. Then revoke all, validate the revocation for each CA cert in the issuer CA history.
        /// </summary>
        [SkippableFact, Trait(Constants.Type, Constants.UnitTest), TestPriority(2000)]
        public async Task CreateCAAndAppCertificatesThenRevokeAll() {
            Skip.If(!_fixture.KeyVaultInitOk);
            var certCollection = new X509Certificate2Collection();
            for (var i = 0; i < 3; i++) {
                await KeyVaultCreateCACertificateAsync();
                for (var v = 0; v < 10; v++) {
                    certCollection.AddRange(await KeyVaultSigningRequestAsync());
                    certCollection.AddRange(await KeyVaultNewKeyPairRequestAsync());
                }
            }

            var groups = await _vaultClient.GetGroupIdsAsync();

            // validate all certificates
            foreach (var group in groups) {
                var trustList = await _vaultClient.GetTrustListAsync(group);
                var nextPageLink = trustList.NextPageLink;
                while (nextPageLink != null) {
                    var nextTrustList = await _vaultClient.GetTrustListAsync(group, nextPageLink);
                    trustList.AddRange(nextTrustList);
                    nextPageLink = nextTrustList.NextPageLink;
                }
                var validator = await X509TestUtils.CreateValidatorAsync(trustList);
                foreach (var cert in certCollection) {
                    validator.Validate(cert);
                }
            }

            // now revoke all certifcates
            var revokeCertificates = new X509Certificate2Collection(certCollection).ToServiceModel(null);
            foreach (var group in groups) {
                var unrevokedCertificates = await _vaultClient.RevokeCertificatesAsync(group, revokeCertificates);
                Assert.True(unrevokedCertificates.Chain.Count <= revokeCertificates.Chain.Count);
                revokeCertificates = unrevokedCertificates;
            }
            Assert.Empty(revokeCertificates.Chain);

            // reload updated trust list from KeyVault
            var trustListAllGroups = new TrustListModel {
                GroupId = "all"
            };
            foreach (var group in groups) {
                var trustList = await _vaultClient.GetTrustListAsync(group);
                var nextPageLink = trustList.NextPageLink;
                while (nextPageLink != null) {
                    var nextTrustList = await _vaultClient.GetTrustListAsync(group, nextPageLink);
                    trustList.AddRange(nextTrustList);
                    nextPageLink = nextTrustList.NextPageLink;
                }
                trustListAllGroups.AddRange(trustList);
            }

            // verify certificates are revoked
            {
                var validator = await X509TestUtils.CreateValidatorAsync(trustListAllGroups);
                foreach (var cert in certCollection) {
                    Assert.Throws<Opc.Ua.ServiceResultException>(() => validator.Validate(cert));
                }
            }
        }

        private readonly VaultClientTestFixture _fixture;
        private readonly DefaultVaultClient _vaultClient;
        private readonly ILogger _logger;
    }
}
