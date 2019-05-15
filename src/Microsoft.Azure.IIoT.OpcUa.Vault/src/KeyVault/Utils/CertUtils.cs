// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace Microsoft.Azure.IIoT.OpcUa.Vault.KeyVault {
    using Opc.Ua;
    using Org.BouncyCastle.Asn1;
    using Org.BouncyCastle.Asn1.X509;
    using Org.BouncyCastle.Crypto;
    using Org.BouncyCastle.Crypto.Parameters;
    using Org.BouncyCastle.Math;
    using Org.BouncyCastle.Security;
    using Org.BouncyCastle.X509;
    using Org.BouncyCastle.X509.Extension;
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Net;
    using System.Security.Cryptography;
    using System.Security.Cryptography.Asn1;
    using System.Security.Cryptography.X509Certificates;
    using System.Text;
    using System.Threading.Tasks;
    using X509Extension = System.Security.Cryptography.X509Certificates.X509Extension;

    /// <summary>
    /// Certificate factory
    /// </summary>
    public static class CertUtils {

        /// <summary>
        /// Creates a KeyVault signed certificate.
        /// </summary>
        /// <returns>The signed certificate</returns>
        public static Task<X509Certificate2> CreateSignedCertificate(string applicationUri,
            string applicationName, string subjectName, IList<string> domainNames,
            ushort keySize, DateTime notBefore, DateTime notAfter, ushort hashSizeInBits,
            X509Certificate2 issuerCAKeyCert, RSA publicKey, X509SignatureGenerator generator,
            bool caCert = false, string extensionUrl = null) {
            if (publicKey == null) {
                throw new NotSupportedException("Need a public key and a CA certificate.");
            }

            if (publicKey.KeySize != keySize) {
                throw new NotSupportedException(
                    string.Format("Public key size {0} does not match expected key size {1}",
                    publicKey.KeySize, keySize));
            }
            // new serial number
            var serialNumber = new byte[kSerialNumberLength];
            RandomNumberGenerator.Fill(serialNumber);
            serialNumber[0] &= 0x7F;

            // set default values.
            var subjectDN = SetSuitableDefaults(ref applicationUri,
                ref applicationName, ref subjectName, ref domainNames, ref keySize);

            var request = new CertificateRequest(subjectDN, publicKey,
                GetRSAHashAlgorithmName(hashSizeInBits), RSASignaturePadding.Pkcs1);

            // Basic constraints
            request.CertificateExtensions.Add(
                new X509BasicConstraintsExtension(caCert, caCert, 0, true));

            // Subject Key Identifier
            var ski = new X509SubjectKeyIdentifierExtension(
                request.PublicKey,
                X509SubjectKeyIdentifierHashAlgorithm.Sha1,
                false);
            request.CertificateExtensions.Add(ski);

            // Authority Key Identifier
            if (issuerCAKeyCert != null) {
                request.CertificateExtensions.Add(
                    BuildAuthorityKeyIdentifier(issuerCAKeyCert));
            }
            else {
                request.CertificateExtensions.Add(
                    BuildAuthorityKeyIdentifier(subjectDN, serialNumber.Reverse().ToArray(), ski));
            }

            if (caCert) {
                request.CertificateExtensions.Add(
                    new X509KeyUsageExtension(
                        X509KeyUsageFlags.DigitalSignature |
                        X509KeyUsageFlags.KeyCertSign |
                        X509KeyUsageFlags.CrlSign, true));
                if (extensionUrl != null) {
                    // add CRL endpoint, if available
                    request.CertificateExtensions.Add(BuildX509CRLDistributionPoints(
                        PatchExtensionUrl(extensionUrl, serialNumber)));
                }
            }
            else {
                // Key Usage
                var defaultFlags =
                    X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.DataEncipherment |
                        X509KeyUsageFlags.NonRepudiation | X509KeyUsageFlags.KeyEncipherment;
                if (issuerCAKeyCert == null) {
                    // self signed case
                    defaultFlags |= X509KeyUsageFlags.KeyCertSign;
                }
                request.CertificateExtensions.Add(
                    new X509KeyUsageExtension(defaultFlags, true));

                // Enhanced key usage
                request.CertificateExtensions.Add(
                    new X509EnhancedKeyUsageExtension(
                        new OidCollection {
                        new Oid("1.3.6.1.5.5.7.3.1"),
                        new Oid("1.3.6.1.5.5.7.3.2") }, true));

                // Subject Alternative Name
                var subjectAltName = BuildSubjectAlternativeName(applicationUri, domainNames);
                request.CertificateExtensions.Add(new X509Extension(subjectAltName, false));

                if (issuerCAKeyCert != null &&
                    extensionUrl != null) {   // add Authority Information Access, if available
                    request.CertificateExtensions.Add(
                        BuildX509AuthorityInformationAccess(new string[] {
                            PatchExtensionUrl(extensionUrl, issuerCAKeyCert.SerialNumber)
                        }));
                }
            }

            if (issuerCAKeyCert != null) {
                if (notAfter > issuerCAKeyCert.NotAfter) {
                    notAfter = issuerCAKeyCert.NotAfter;
                }
                if (notBefore < issuerCAKeyCert.NotBefore) {
                    notBefore = issuerCAKeyCert.NotBefore;
                }
            }

            var issuerSubjectName = issuerCAKeyCert != null ? issuerCAKeyCert.SubjectName : subjectDN;
            var signedCert = request.Create(issuerSubjectName, generator, notBefore, notAfter, serialNumber);
            return Task.FromResult(signedCert);
        }

        /// <summary>
        /// Revoke the certificate.
        /// The CRL number is increased by one and the new CRL is returned.
        /// </summary>
        public static X509CRL RevokeCertificate(X509Certificate2 issuerCertificate,
            List<X509CRL> issuerCrls, X509Certificate2Collection revokedCertificates,
            DateTime thisUpdate, DateTime nextUpdate, X509SignatureGenerator generator,
            uint hashSize) {
            var crlSerialNumber = BigInteger.Zero;
            var bcCertCA = new X509CertificateParser().ReadCertificate(issuerCertificate.RawData);
            ISignatureFactory signatureFactory =
                    new KeyVaultSignatureFactory(GetRSAHashAlgorithmName(hashSize), generator);

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
                    crlGen.AddCrlEntry(GetSerialNumber(revokedCertificate),
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
            var updatedCrl = crlGen.Generate(signatureFactory);
            return new X509CRL(updatedCrl.GetEncoded());
        }

        /// <summary>
        /// Get RSA public key from a CSR.
        /// </summary>
        public static RSA GetRSAPublicKey(SubjectPublicKeyInfo subjectPublicKeyInfo) {
            var asymmetricKeyParameter = PublicKeyFactory.CreateKey(subjectPublicKeyInfo);
            var rsaKeyParameters = (RsaKeyParameters)asymmetricKeyParameter;
            var rsaKeyInfo = new RSAParameters {
                Modulus = rsaKeyParameters.Modulus.ToByteArrayUnsigned(),
                Exponent = rsaKeyParameters.Exponent.ToByteArrayUnsigned()
            };
            var rsa = RSA.Create(rsaKeyInfo);
            return rsa;
        }

#if UNUSED
        private static string GetRSAHashAlgorithm(uint hashSizeInBits) {
            if (hashSizeInBits <= 160) {
                return "SHA1WITHRSA";
            }

            if (hashSizeInBits <= 224) {
                return "SHA224WITHRSA";
            }
            else if (hashSizeInBits <= 256) {
                return "SHA256WITHRSA";
            }
            else if (hashSizeInBits <= 384) {
                return "SHA384WITHRSA";
            }
            else {
                return "SHA512WITHRSA";
            }
        }
#endif
        /// <summary>
        /// Get name of algorithm based on bits
        /// </summary>
        /// <param name="hashSizeInBits"></param>
        /// <returns></returns>
        private static HashAlgorithmName GetRSAHashAlgorithmName(uint hashSizeInBits) {
            if (hashSizeInBits <= 160) {
                return HashAlgorithmName.SHA1;
            }
            if (hashSizeInBits <= 256) {
                return HashAlgorithmName.SHA256;
            }
            else if (hashSizeInBits <= 384) {
                return HashAlgorithmName.SHA384;
            }
            else {
                return HashAlgorithmName.SHA512;
            }
        }

        /// <summary>
        /// Read the Crl number from a X509Crl.
        /// </summary>
        private static BigInteger GetCrlNumber(X509Crl crl) {
            var crlNumber = BigInteger.One;
            try {
                var asn1Object = GetExtensionValue(crl, X509Extensions.CrlNumber);
                if (asn1Object != null) {
                    crlNumber = DerInteger.GetInstance(asn1Object).PositiveValue;
                }
            }
            finally {
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

#if UNUSED
        /// <summary>
        /// Get public key parameters from a X509Certificate2
        /// </summary>
        private static RsaKeyParameters GetPublicKeyParameter(
            X509Certificate2 certificate) {
            using (var rsa = certificate.GetRSAPublicKey()) {
                var rsaParams = rsa.ExportParameters(false);
                return new RsaKeyParameters(false,
                    new BigInteger(1, rsaParams.Modulus),
                    new BigInteger(1, rsaParams.Exponent));
            }
        }
#endif

        /// <summary>
        /// Get the serial number from a certificate as BigInteger.
        /// </summary>
        private static BigInteger GetSerialNumber(X509Certificate2 certificate) {
            var serialNumber = certificate.GetSerialNumber();
            Array.Reverse(serialNumber);
            return new BigInteger(1, serialNumber);
        }

        /// <summary>
        /// Sets the parameters to suitable defaults.
        /// </summary>
        private static X500DistinguishedName SetSuitableDefaults(ref string applicationUri,
            ref string applicationName, ref string subjectName, ref IList<string> domainNames,
            ref ushort keySize) {
            // enforce recommended keysize unless lower value is enforced.
            if (keySize < 2048) {
                keySize = kDefaultKeySize;
            }

            if (keySize % 1024 != 0) {
                throw new ArgumentNullException(nameof(keySize),
                    "KeySize must be a multiple of 1024.");
            }

            // parse the subject name if specified.
            List<string> subjectNameEntries = null;

            if (!string.IsNullOrEmpty(subjectName)) {
                subjectNameEntries = Utils.ParseDistinguishedName(subjectName);
                // enforce proper formatting for the subject name string
                subjectName = string.Join(", ", subjectNameEntries);
            }

            // check the application name.
            if (string.IsNullOrEmpty(applicationName)) {
                if (subjectNameEntries == null) {
                    throw new ArgumentNullException(nameof(applicationName),
                        "Must specify a applicationName or a subjectName.");
                }
                // use the common name as the application name.
                foreach (var entry in subjectNameEntries) {
                    if (entry.StartsWith("CN=", StringComparison.InvariantCulture)) {
                        applicationName = entry.Substring(3).Trim();
                        break;
                    }
                }
            }

            if (string.IsNullOrEmpty(applicationName)) {
                throw new ArgumentNullException(nameof(applicationName),
                    "Must specify a applicationName or a subjectName.");
            }

            // remove special characters from name.
            var buffer = new StringBuilder();

            foreach (var ch in applicationName) {
                if (char.IsControl(ch) || ch == '/' || ch == ',' || ch == ';') {
                    buffer.Append('+');
                }
                else {
                    buffer.Append(ch);
                }
            }

            applicationName = buffer.ToString();

            // ensure at least one host name.
            if (domainNames == null || domainNames.Count == 0) {
                domainNames = new List<string> {
                    Utils.GetHostName()
                };
            }

            // create the application uri.
            if (string.IsNullOrEmpty(applicationUri)) {
                var builder = new StringBuilder();

                builder.Append("urn:");
                builder.Append(domainNames[0]);
                builder.Append(":");
                builder.Append(applicationName);

                applicationUri = builder.ToString();
            }

            var uri = Utils.ParseUri(applicationUri);

            if (uri == null) {
                throw new ArgumentNullException(nameof(applicationUri),
                    "Must specify a valid URL.");
            }

            // create the subject name,
            if (string.IsNullOrEmpty(subjectName)) {
                subjectName = Utils.Format("CN={0}", applicationName);
            }

            if (!subjectName.Contains("CN=")) {
                subjectName = Utils.Format("CN={0}", subjectName);
            }

            if (domainNames != null && domainNames.Count > 0) {
                if (!subjectName.Contains("DC=") && !subjectName.Contains("=")) {
                    subjectName += Utils.Format(", DC={0}", domainNames[0]);
                }
                else {
                    subjectName = Utils.ReplaceDCLocalhost(subjectName, domainNames[0]);
                }
            }

            return new X500DistinguishedName(subjectName);
        }

        /// <summary>
        /// Build the Subject Alternative name extension (for OPC UA application certs)
        /// </summary>
        /// <param name="applicationUri">The application Uri</param>
        /// <param name="domainNames">The domain names.
        /// DNS Hostnames, IPv4 or IPv6 addresses</param>
        private static X509Extension BuildSubjectAlternativeName(string applicationUri,
            IList<string> domainNames) {
            var sanBuilder = new SubjectAlternativeNameBuilder();
            sanBuilder.AddUri(new Uri(applicationUri));
            foreach (var domainName in domainNames) {
                if (string.IsNullOrWhiteSpace(domainName)) {
                    continue;
                }
                if (IPAddress.TryParse(domainName, out var ipAddr)) {
                    sanBuilder.AddIpAddress(ipAddr);
                }
                else {
                    sanBuilder.AddDnsName(domainName);
                }
            }

            return sanBuilder.Build();
        }

        /// <summary>
        /// Convert a hex string to a byte array.
        /// </summary>
        /// <param name="hexString">The hex string</param>
        internal static byte[] HexToByteArray(string hexString) {
            var bytes = new byte[hexString.Length / 2];

            for (var i = 0; i < hexString.Length; i += 2) {
                var s = hexString.Substring(i, 2);
                bytes[i / 2] = byte.Parse(s, System.Globalization.NumberStyles.HexNumber, null);
            }

            return bytes;
        }

        /// <summary>
        /// Build the Authority Key Identifier from an Issuer CA certificate.
        /// </summary>
        /// <param name="issuerCaCertificate">The issuer CA certificate</param>
        private static X509Extension BuildAuthorityKeyIdentifier(X509Certificate2 issuerCaCertificate) {
            // force exception if SKI is not present
            var ski = issuerCaCertificate.Extensions
                .OfType<X509SubjectKeyIdentifierExtension>()
                .Single();
            return BuildAuthorityKeyIdentifier(issuerCaCertificate.SubjectName,
                issuerCaCertificate.GetSerialNumber(), ski);
        }

        /// <summary>
        /// Build the CRL Distribution Point extension.
        /// </summary>
        /// <param name="distributionPoint">The CRL distribution point</param>
        private static X509Extension BuildX509CRLDistributionPoints(string distributionPoint) {
            var context0 = new Asn1Tag(TagClass.ContextSpecific, 0, true);
            var distributionPointChoice = context0;
            var fullNameChoice = context0;
            var generalNameUriChoice = new Asn1Tag(TagClass.ContextSpecific, 6);
            using (var writer = new AsnWriter(AsnEncodingRules.DER)) {
                writer.PushSequence();
                writer.PushSequence();
                writer.PushSequence(distributionPointChoice);
                writer.PushSequence(fullNameChoice);
                writer.WriteCharacterString(
                    generalNameUriChoice,
                    UniversalTagNumber.IA5String,
                    distributionPoint);
                writer.PopSequence(fullNameChoice);
                writer.PopSequence(distributionPointChoice);
                writer.PopSequence();
                writer.PopSequence();
                return new X509Extension("2.5.29.31", writer.Encode(), false);
            }
        }

        /// <summary>
        /// Build the Authority information Access extension.
        /// </summary>
        /// <param name="caIssuerUrls">Array of CA Issuer Urls</param>
        /// <param name="ocspResponder">optional, the OCSP responder </param>
        private static X509Extension BuildX509AuthorityInformationAccess(string[] caIssuerUrls,
            string ocspResponder = null) {
            if (string.IsNullOrEmpty(ocspResponder) &&
               (caIssuerUrls == null ||
               (caIssuerUrls != null && caIssuerUrls.Length == 0))) {
                throw new ArgumentNullException(nameof(caIssuerUrls),
                    "One CA Issuer Url or OCSP responder is required for the extension.");
            }
            var context0 = new Asn1Tag(TagClass.ContextSpecific, 0, true);
            var generalNameUriChoice = new Asn1Tag(TagClass.ContextSpecific, 6);
            using (var writer = new AsnWriter(AsnEncodingRules.DER)) {
                writer.PushSequence();
                if (caIssuerUrls != null) {
                    foreach (var caIssuerUrl in caIssuerUrls) {
                        writer.PushSequence();
                        writer.WriteObjectIdentifier("1.3.6.1.5.5.7.48.2");
                        writer.WriteCharacterString(
                            generalNameUriChoice,
                            UniversalTagNumber.IA5String,
                            caIssuerUrl);
                        writer.PopSequence();
                    }
                }
                if (!string.IsNullOrEmpty(ocspResponder)) {
                    writer.PushSequence();
                    writer.WriteObjectIdentifier("1.3.6.1.5.5.7.48.1");
                    writer.WriteCharacterString(
                        generalNameUriChoice,
                        UniversalTagNumber.IA5String,
                        ocspResponder);
                    writer.PopSequence();
                }
                writer.PopSequence();
                return new X509Extension("1.3.6.1.5.5.7.1.1", writer.Encode(), false);
            }
        }

        /// <summary>
        /// Build the X509 Authority Key extension.
        /// </summary>
        /// <param name="issuerName">The distinguished name of the issuer</param>
        /// <param name="issuerSerialNumber">The serial number of the issuer</param>
        /// <param name="ski">The subject key identifier extension to use</param>
        private static X509Extension BuildAuthorityKeyIdentifier(X500DistinguishedName issuerName,
            byte[] issuerSerialNumber, X509SubjectKeyIdentifierExtension ski) {
            using (var writer = new AsnWriter(AsnEncodingRules.DER)) {
                writer.PushSequence();

                if (ski != null) {
                    var keyIdTag = new Asn1Tag(TagClass.ContextSpecific, 0);
                    writer.WriteOctetString(keyIdTag, HexToByteArray(ski.SubjectKeyIdentifier));
                }

                var issuerNameTag = new Asn1Tag(TagClass.ContextSpecific, 1);
                writer.PushSequence(issuerNameTag);

                // Add the tag to constructed context-specific 4 (GeneralName.directoryName)
                var directoryNameTag = new Asn1Tag(TagClass.ContextSpecific, 4, true);
                writer.PushSetOf(directoryNameTag);
                var issuerNameRaw = issuerName.RawData;
                writer.WriteEncodedValue(issuerNameRaw);
                writer.PopSetOf(directoryNameTag);
                writer.PopSequence(issuerNameTag);

                var issuerSerialTag = new Asn1Tag(TagClass.ContextSpecific, 2);
                var issuerSerial = new System.Numerics.BigInteger(issuerSerialNumber);
                writer.WriteInteger(issuerSerialTag, issuerSerial);

                writer.PopSequence();
                return new X509Extension("2.5.29.35", writer.Encode(), false);
            }
        }

        /// <summary>
        /// Patch serial number in a Url. byte version.
        /// </summary>
        private static string PatchExtensionUrl(string extensionUrl, byte[] serialNumber) {
            var serial = BitConverter.ToString(serialNumber).Replace("-", "");
            return PatchExtensionUrl(extensionUrl, serial);
        }

        /// <summary>
        /// Patch serial number in a Url. string version.
        /// </summary>
        private static string PatchExtensionUrl(string extensionUrl, string serial) {
            return extensionUrl.Replace("%serial%", serial.ToLower());
        }

        private const int kSerialNumberLength = 20;
        private const int kDefaultKeySize = 2048;
    }
}
