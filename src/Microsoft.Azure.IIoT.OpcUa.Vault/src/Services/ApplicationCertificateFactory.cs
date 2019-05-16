// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace Microsoft.Azure.IIoT.OpcUa.Vault.KeyVault {
    using Microsoft.Azure.IIoT.OpcUa.Vault.KeyVault.Models;
    using Serilog;
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Net;
    using System.Security.Cryptography;
    using System.Security.Cryptography.Asn1;
    using System.Security.Cryptography.X509Certificates;
    using System.Text;
    using System.Threading.Tasks;
    using Opc.Ua;

    /// <summary>
    /// OPC UA Application certificate factory
    /// </summary>
    public class ApplicationCertificateFactory : IApplicationCertificateFactory {

        /// <summary>
        /// Create factory
        /// </summary>
        /// <param name="signer"></param>
        /// <param name="logger"></param>
        public ApplicationCertificateFactory(IDigestSigner signer, ILogger logger) {
            _signer = signer ?? throw new ArgumentNullException(nameof(signer));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        /// <inheritdoc/>
        public Task<X509Certificate2> CreateSignedCertificate(X509CertificateKeyIdPair issuerCAKeyCert,
            RSA publicKey, string applicationUri, string applicationName, string subjectName,
            IList<string> domainNames, ushort keySize, DateTime notBefore, DateTime notAfter,
            ushort hashSizeInBits, string extensionUrl) {

            if (publicKey == null) {
                throw new ArgumentNullException(nameof(publicKey), "Need a public key.");
            }
            if (issuerCAKeyCert == null) {
                throw new ArgumentNullException(nameof(issuerCAKeyCert), "Need a root cert.");
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
                CertUtils.GetRSAHashAlgorithmName(hashSizeInBits), RSASignaturePadding.Pkcs1);

            // Basic constraints
            request.CertificateExtensions.Add(
                new X509BasicConstraintsExtension(false, false, 0, true));

            // Subject Key Identifier
            var ski = new X509SubjectKeyIdentifierExtension(
                request.PublicKey,
                X509SubjectKeyIdentifierHashAlgorithm.Sha1,
                false);
            request.CertificateExtensions.Add(ski);

            // Authority Key Identifier
            if (issuerCAKeyCert != null) {
                request.CertificateExtensions.Add(
                    BuildAuthorityKeyIdentifier(issuerCAKeyCert.Certificate));
            }
            else {
                request.CertificateExtensions.Add(
                    BuildAuthorityKeyIdentifier(subjectDN, serialNumber.Reverse().ToArray(), ski));
            }

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

            if (extensionUrl != null) {   // add Authority Information Access, if available
                request.CertificateExtensions.Add(
                    BuildX509AuthorityInformationAccess(new string[] {
                        PatchExtensionUrl(extensionUrl, issuerCAKeyCert.Certificate.SerialNumber)
                    }));
            }

            if (notAfter > issuerCAKeyCert.Certificate.NotAfter) {
                notAfter = issuerCAKeyCert.Certificate.NotAfter;
            }
            if (notBefore < issuerCAKeyCert.Certificate.NotBefore) {
                notBefore = issuerCAKeyCert.Certificate.NotBefore;
            }
            var issuerSubjectName = issuerCAKeyCert != null ?
                issuerCAKeyCert.Certificate.SubjectName : subjectDN;
            var signatureGenerator = new SignatureGenerator(_signer, issuerCAKeyCert);
            var signedCert = request.Create(issuerSubjectName, signatureGenerator, notBefore,
                notAfter, serialNumber);
            return Task.FromResult(signedCert);
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
                    Dns.GetHostName()
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

            var uri = Opc.Ua.Utils.ParseUri(applicationUri);

            if (uri == null) {
                throw new ArgumentNullException(nameof(applicationUri),
                    "Must specify a valid URL.");
            }

            // create the subject name,
            if (string.IsNullOrEmpty(subjectName)) {
                subjectName = "CN=" + applicationName;
            }

            if (!subjectName.Contains("CN=")) {
                subjectName = "CN=" + subjectName;
            }

            if (domainNames != null && domainNames.Count > 0) {
                if (!subjectName.Contains("DC=") && !subjectName.Contains("=")) {
                    subjectName += ", DC=" + domainNames[0];
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
        /// Patch serial number in a Url. string version.
        /// </summary>
        private static string PatchExtensionUrl(string extensionUrl, string serial) {
            return extensionUrl.Replace("%serial%", serial.ToLower());
        }

        private const int kSerialNumberLength = 20;
        private const int kDefaultKeySize = 2048;
        private readonly IDigestSigner _signer;
        private readonly ILogger _logger;
    }
}
