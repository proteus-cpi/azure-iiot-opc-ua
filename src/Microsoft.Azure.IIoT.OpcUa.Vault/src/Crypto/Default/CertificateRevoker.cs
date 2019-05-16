// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace Microsoft.Azure.IIoT.OpcUa.Vault.KeyVault {
    using Microsoft.Azure.IIoT.OpcUa.Vault.KeyVault.Models;
    using Serilog;
    using Org.BouncyCastle.Asn1;
    using Org.BouncyCastle.Asn1.X509;
    using Org.BouncyCastle.Math;
    using Org.BouncyCastle.Security;
    using Org.BouncyCastle.X509;
    using Org.BouncyCastle.X509.Extension;
    using System;
    using System.Collections.Generic;
    using System.Security.Cryptography.X509Certificates;

    /// <summary>
    /// Default certificate revoker
    /// </summary>
    public class CertificateRevoker : ICrlFactory {

        /// <summary>
        /// Create factory
        /// </summary>
        /// <param name="signer"></param>
        /// <param name="logger"></param>
        public CertificateRevoker(IDigestSigner signer, ILogger logger) {
            _signer = signer;
            _logger = logger;
        }

        /// <inheritdoc/>
        public X509Crl2 CreateCrl(X509CertificateKeyIdPair issuerCertificate) {
            if (issuerCertificate == null) {
                throw new ArgumentNullException(nameof(issuerCertificate));
            }
            if (issuerCertificate.Certificate == null) {
                throw new ArgumentNullException(nameof(issuerCertificate.Certificate));
            }
            if (string.IsNullOrEmpty(issuerCertificate.KeyIdentifier)) {
                throw new ArgumentException("Issuer certificate has no private key," +
                    " cannot revoke certificate.");
            }
            using (var rand = new RandomGeneratorAdapter()) {
                // cert generators
                var random = new SecureRandom(rand);
                var crlSerialNumber = BigInteger.Zero;

                var bcCertCA = new X509CertificateParser().ReadCertificate(
                    issuerCertificate.Certificate.RawData);
                var signatureGenerator = new SignatureGeneratorAdapter(_signer, issuerCertificate);
                var signatureFactory = new SignatureFactory(CertUtils.GetRSAHashAlgorithmName(256),
                    signatureGenerator);

                var crlGen = new X509V2CrlGenerator();
                crlGen.SetIssuerDN(bcCertCA.IssuerDN);
                crlGen.SetThisUpdate(DateTime.UtcNow);
                crlGen.SetNextUpdate(DateTime.UtcNow.AddMonths(12));

                var now = DateTime.UtcNow;
                crlGen.AddCrlEntry(BigInteger.One, now, CrlReason.Unspecified);
                crlGen.AddExtension(X509Extensions.AuthorityKeyIdentifier, false,
                    new AuthorityKeyIdentifierStructure(bcCertCA));

                // set new serial number
                crlSerialNumber = crlSerialNumber.Add(BigInteger.One);
                crlGen.AddExtension(X509Extensions.CrlNumber, false,
                    new CrlNumber(crlSerialNumber));

                // generate updated CRL
                var updatedCrl = crlGen.Generate(signatureFactory);
                return new X509Crl2(updatedCrl.GetEncoded());
            }
        }

        /// <inheritdoc/>
        public X509Crl2 RevokeCertificate(X509CertificateKeyIdPair issuerCertificate,
            IEnumerable<X509Crl2> issuerCrls, X509Certificate2Collection revokedCertificates,
            DateTime thisUpdate, DateTime nextUpdate, uint hashSize) {

            if (issuerCertificate == null) {
                throw new ArgumentNullException(nameof(issuerCertificate));
            }
            if (issuerCertificate.Certificate == null) {
                throw new ArgumentNullException(nameof(issuerCertificate.Certificate));
            }
            if (string.IsNullOrEmpty(issuerCertificate.KeyIdentifier)) {
                throw new ArgumentException("Issuer certificate has no private key," +
                    " cannot revoke certificate.");
            }

            var bcCertCA = new X509CertificateParser().ReadCertificate(
                issuerCertificate.Certificate.RawData);

            var crlGen = new X509V2CrlGenerator();
            crlGen.SetIssuerDN(bcCertCA.IssuerDN);
            if (thisUpdate == DateTime.MinValue) {
                thisUpdate = DateTime.UtcNow;
            }
            crlGen.SetThisUpdate(thisUpdate);
            if (nextUpdate <= thisUpdate) {
                nextUpdate = bcCertCA.NotAfter;
            }
            crlGen.SetNextUpdate(nextUpdate);

            var crlSerialNumber = BigInteger.Zero;
            // merge all existing revocation list
            if (issuerCrls != null) {
                var parser = new X509CrlParser();
                foreach (var issuerCrl in issuerCrls) {
                    var crl = parser.ReadCrl(issuerCrl.RawData);
                    crlGen.AddCrl(crl);
                    var crlVersion = GetCrlNumber(crl);
                    if (crlVersion.IntValue > crlSerialNumber.IntValue) {
                        crlSerialNumber = crlVersion;
                    }
                }
            }
            if (revokedCertificates == null || revokedCertificates.Count == 0) {
                // add a dummy revoked cert
                crlGen.AddCrlEntry(BigInteger.One, thisUpdate, CrlReason.Unspecified);
            }
            else {
                // add the revoked cert
                foreach (var revokedCertificate in revokedCertificates) {
                    crlGen.AddCrlEntry(revokedCertificate.GetSerialNumberAsBigInteger(),
                        thisUpdate, CrlReason.PrivilegeWithdrawn);
                }
            }

            crlGen.AddExtension(X509Extensions.AuthorityKeyIdentifier, false,
                new AuthorityKeyIdentifierStructure(bcCertCA));

            // set new serial number
            crlSerialNumber = crlSerialNumber.Add(BigInteger.One);
            crlGen.AddExtension(X509Extensions.CrlNumber, false,
                new CrlNumber(crlSerialNumber));

            // generate updated CRL
            var signatureGenerator = new SignatureGeneratorAdapter(_signer, issuerCertificate);
            var signatureFactory = new SignatureFactory(CertUtils.GetRSAHashAlgorithmName(hashSize),
                signatureGenerator);
            var updatedCrl = crlGen.Generate(signatureFactory);
            return new X509Crl2(updatedCrl.GetEncoded());
        }

        /// <summary>
        /// Read the Crl number from a X509Crl.
        /// </summary>
        private static BigInteger GetCrlNumber(X509Crl crl) {
            var crlNumber = BigInteger.One;
            var asn1Object = GetExtensionValue(crl, X509Extensions.CrlNumber);
            if (asn1Object != null) {
                crlNumber = DerInteger.GetInstance(asn1Object).PositiveValue;
            }
            return crlNumber;
        }

        /// <summary>
        /// Get the value of an extension oid.
        /// </summary>
        private static Asn1Object GetExtensionValue(
            IX509Extension extension, DerObjectIdentifier oid) {
            var asn1Octet = extension.GetExtensionValue(oid);
            if (asn1Octet != null) {
                return X509ExtensionUtilities.FromExtensionValue(asn1Octet);
            }
            return null;
        }

        private readonly IDigestSigner _signer;
        private readonly ILogger _logger;
    }
}
