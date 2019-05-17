// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace Microsoft.Azure.IIoT.OpcUa.Vault.Tests {
    using Microsoft.Azure.IIoT.Crypto.Models;
    using Microsoft.Azure.IIoT.OpcUa.Registry.Tests;
    using Microsoft.Azure.IIoT.OpcUa.Vault.Models;
    using Opc.Ua;
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Security.Cryptography.X509Certificates;
    using System.Threading.Tasks;
    using Xunit;


    public static class X509TestUtils {
        public static void VerifyApplicationCertIntegrity(
            X509Certificate2 newCert,
            byte[] privateKey,
            string privateKeyPassword,
            PrivateKeyFormat privateKeyFormat,
            X509Certificate2Collection issuerCertificates) {
            Assert.NotNull(newCert);
            if (privateKey != null) {
                X509Certificate2 newPrivateKeyCert = null;
                if (privateKeyFormat == PrivateKeyFormat.PFX) {
                    newPrivateKeyCert = CertificateFactory.CreateCertificateFromPKCS12(privateKey, privateKeyPassword);
                }
                else if (privateKeyFormat == PrivateKeyFormat.PEM) {
                    newPrivateKeyCert = CertificateFactory.CreateCertificateWithPEMPrivateKey(newCert, privateKey, privateKeyPassword);
                }
                else {
                    Assert.True(false, "Invalid private key format");
                }
                Assert.NotNull(newPrivateKeyCert);
                // verify the public cert matches the private key
                Assert.True(CertificateFactory.VerifyRSAKeyPair(newCert, newPrivateKeyCert, true));
                Assert.True(CertificateFactory.VerifyRSAKeyPair(newPrivateKeyCert, newPrivateKeyCert, true));
            }

            var issuerCertIdCollection = new CertificateIdentifierCollection();
            foreach (var issuerCert in issuerCertificates) {
                issuerCertIdCollection.Add(new CertificateIdentifier(issuerCert));
            }

            // verify cert with issuer chain
            var certValidator = new CertificateValidator();
            var issuerStore = new CertificateTrustList();
            var trustedStore = new CertificateTrustList {
                TrustedCertificates = issuerCertIdCollection
            };
            certValidator.Update(trustedStore, issuerStore, null);
            Assert.Throws<ServiceResultException>(() => certValidator.Validate(newCert));
            issuerStore.TrustedCertificates = issuerCertIdCollection;
            certValidator.Update(issuerStore, trustedStore, null);
            certValidator.Validate(newCert);
        }

        public static void VerifySignedApplicationCert(ApplicationTestData testApp,
            X509Certificate2 signedCert, X509Certificate2Collection issuerCerts) {
            var issuerCert = issuerCerts[0];

            Assert.NotNull(signedCert);
            Assert.False(signedCert.HasPrivateKey);
            Assert.True(Utils.CompareDistinguishedName(testApp.Subject, signedCert.Subject));
            Assert.False(Utils.CompareDistinguishedName(signedCert.Issuer, signedCert.Subject));
            Assert.True(Utils.CompareDistinguishedName(signedCert.Issuer, issuerCert.Subject));

            // test basic constraints
            var constraints = FindBasicConstraintsExtension(signedCert);
            Assert.NotNull(constraints);
            Assert.True(constraints.Critical);
            Assert.False(constraints.CertificateAuthority);
            Assert.False(constraints.HasPathLengthConstraint);

            // key usage
            var keyUsage = FindKeyUsageExtension(signedCert);
            Assert.NotNull(keyUsage);
            Assert.True(keyUsage.Critical);
            Assert.True((keyUsage.KeyUsages & X509KeyUsageFlags.CrlSign) == 0);
            Assert.True((keyUsage.KeyUsages & X509KeyUsageFlags.DataEncipherment) == X509KeyUsageFlags.DataEncipherment);
            Assert.True((keyUsage.KeyUsages & X509KeyUsageFlags.DecipherOnly) == 0);
            Assert.True((keyUsage.KeyUsages & X509KeyUsageFlags.DigitalSignature) == X509KeyUsageFlags.DigitalSignature);
            Assert.True((keyUsage.KeyUsages & X509KeyUsageFlags.EncipherOnly) == 0);
            Assert.True((keyUsage.KeyUsages & X509KeyUsageFlags.KeyAgreement) == 0);
            Assert.True((keyUsage.KeyUsages & X509KeyUsageFlags.KeyCertSign) == 0);
            Assert.True((keyUsage.KeyUsages & X509KeyUsageFlags.KeyEncipherment) == X509KeyUsageFlags.KeyEncipherment);
            Assert.True((keyUsage.KeyUsages & X509KeyUsageFlags.NonRepudiation) == X509KeyUsageFlags.NonRepudiation);

            // enhanced key usage
            var enhancedKeyUsage = FindEnhancedKeyUsageExtension(signedCert);
            Assert.NotNull(enhancedKeyUsage);
            Assert.True(enhancedKeyUsage.Critical);

            // test for authority key
            var authority = FindAuthorityKeyIdentifier(signedCert);
            Assert.NotNull(authority);
            Assert.NotNull(authority.SerialNumber);
            Assert.NotNull(authority.KeyId);
            Assert.NotNull(authority.AuthorityNames);

            // verify authority key in signed cert
            var subjectKeyId = FindSubjectKeyIdentifierExtension(issuerCert);
            Assert.Equal(subjectKeyId.SubjectKeyIdentifier, authority.KeyId);
            Assert.Equal(issuerCert.SerialNumber, authority.SerialNumber);

            var subjectAlternateName = FindSubjectAltName(signedCert);
            Assert.NotNull(subjectAlternateName);
            Assert.False(subjectAlternateName.Critical);
            var domainNames = Utils.GetDomainsFromCertficate(signedCert);
            foreach (var domainName in testApp.DomainNames) {
                Assert.Contains(domainName, domainNames, StringComparer.OrdinalIgnoreCase);
            }
            Assert.True(subjectAlternateName.Uris.Count == 1);
            var applicationUri = Utils.GetApplicationUriFromCertificate(signedCert);
            Assert.True(testApp.ApplicationRecord.ApplicationUri == applicationUri);

            var issuerCertIdCollection = new CertificateIdentifierCollection();
            foreach (var cert in issuerCerts) {
                issuerCertIdCollection.Add(new CertificateIdentifier(cert));
            }

            // verify cert with issuer chain
            var certValidator = new CertificateValidator();
            var issuerStore = new CertificateTrustList();
            var trustedStore = new CertificateTrustList {
                TrustedCertificates = issuerCertIdCollection
            };
            certValidator.Update(trustedStore, issuerStore, null);
            Assert.Throws<ServiceResultException>(() => certValidator.Validate(signedCert));
            issuerStore.TrustedCertificates = issuerCertIdCollection;
            certValidator.Update(issuerStore, trustedStore, null);
            certValidator.Validate(signedCert);

        }

        internal static async Task<CertificateValidator> CreateValidatorAsync(TrustListModel trustList) {
            var storePath = "%LocalApplicationData%/OPCVaultTest/pki/";
            DeleteDirectory(storePath);

            // verify cert with issuer chain
            var certValidator = new CertificateValidator();
            var issuerTrustList = await CreateTrustListAsync(
                storePath + "issuer",
                trustList.IssuerCertificates.ToStackModel(),
                trustList.IssuerCrls.ToStackModel()
                );
            var trustedTrustList = await CreateTrustListAsync(
                storePath + "trusted",
                trustList.TrustedCertificates.ToStackModel(),
                trustList.TrustedCrls.ToStackModel()
                );

            certValidator.Update(issuerTrustList, trustedTrustList, null);
            return certValidator;
        }

        internal static async Task<CertificateTrustList> CreateTrustListAsync(
            string storePath,
            X509Certificate2Collection certCollection,
            IList<X509Crl2> crlCollection) {
            var certTrustList = new CertificateTrustList {
                StoreType = CertificateStoreType.Directory,
                StorePath = storePath
            };
            using (var store = certTrustList.OpenStore()) {
                foreach (var cert in certCollection) {
                    await store.Add(cert);
                }
                if (store.SupportsCRLs) {
                    foreach (var crl in crlCollection) {
                        store.AddCRL(new X509CRL(crl.RawData));
                    }
                }
            }
            return certTrustList;
        }

        internal static X509BasicConstraintsExtension FindBasicConstraintsExtension(X509Certificate2 certificate) {
            for (var ii = 0; ii < certificate.Extensions.Count; ii++) {
                if (certificate.Extensions[ii] is X509BasicConstraintsExtension extension) {
                    return extension;
                }
            }
            return null;
        }

        internal static X509KeyUsageExtension FindKeyUsageExtension(X509Certificate2 certificate) {
            for (var ii = 0; ii < certificate.Extensions.Count; ii++) {
                if (certificate.Extensions[ii] is X509KeyUsageExtension extension) {
                    return extension;
                }
            }
            return null;
        }
        internal static X509EnhancedKeyUsageExtension FindEnhancedKeyUsageExtension(X509Certificate2 certificate) {
            for (var ii = 0; ii < certificate.Extensions.Count; ii++) {
                if (certificate.Extensions[ii] is X509EnhancedKeyUsageExtension extension) {
                    return extension;
                }
            }
            return null;
        }

        internal static X509AuthorityKeyIdentifierExtension FindAuthorityKeyIdentifier(X509Certificate2 certificate) {
            for (var ii = 0; ii < certificate.Extensions.Count; ii++) {
                var extension = certificate.Extensions[ii];

                switch (extension.Oid.Value) {
                    case X509AuthorityKeyIdentifierExtension.AuthorityKeyIdentifierOid:
                    case X509AuthorityKeyIdentifierExtension.AuthorityKeyIdentifier2Oid:
                        return new X509AuthorityKeyIdentifierExtension(extension, extension.Critical);
                }
            }

            return null;
        }

        internal static X509SubjectAltNameExtension FindSubjectAltName(X509Certificate2 certificate) {
            foreach (var extension in certificate.Extensions) {
                if (extension.Oid.Value == X509SubjectAltNameExtension.SubjectAltNameOid ||
                    extension.Oid.Value == X509SubjectAltNameExtension.SubjectAltName2Oid) {
                    return new X509SubjectAltNameExtension(extension, extension.Critical);
                }
            }
            return null;
        }

        internal static X509SubjectKeyIdentifierExtension FindSubjectKeyIdentifierExtension(X509Certificate2 certificate) {
            for (var ii = 0; ii < certificate.Extensions.Count; ii++) {
                if (certificate.Extensions[ii] is X509SubjectKeyIdentifierExtension extension) {
                    return extension;
                }
            }
            return null;
        }

        public static void CleanupTrustList(ICertificateStore _store) {
            using (var store = _store) {
                var certs = store.Enumerate().Result;
                foreach (var cert in certs) {
                    store.Delete(cert.Thumbprint);
                }
                var crls = store.EnumerateCRLs();
                foreach (var crl in crls) {
                    store.DeleteCRL(crl);
                }
            }
        }

        public static void DeleteDirectory(string storePath) {
            try {
                var fullStorePath = Utils.ReplaceSpecialFolderNames(storePath);
                if (Directory.Exists(fullStorePath)) {
                    Directory.Delete(fullStorePath, true);
                }
            }
#pragma warning disable RECS0022 // A catch clause that catches System.Exception and has an empty body
            catch {
#pragma warning restore RECS0022 // A catch clause that catches System.Exception and has an empty body
                // intentionally ignore errors
            }
        }
    }

}
