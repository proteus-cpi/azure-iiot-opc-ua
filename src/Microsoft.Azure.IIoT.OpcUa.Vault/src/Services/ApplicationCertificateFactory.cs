// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace Microsoft.Azure.IIoT.OpcUa.Vault.Services {
    using Microsoft.Azure.IIoT.OpcUa.Vault;
    using Microsoft.Azure.IIoT.Crypto;
    using Microsoft.Azure.IIoT.Crypto.BouncyCastle;
    using Microsoft.Azure.IIoT.Crypto.Models;
    using Microsoft.Azure.IIoT.Crypto.Utils;
    using Opc.Ua;
    using Serilog;
    using System;
    using System.Collections.Generic;
    using System.Net;
    using System.Security.Cryptography;
    using System.Security.Cryptography.X509Certificates;
    using System.Text;
    using System.Threading.Tasks;

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
        public Task<X509Certificate2> CreateSignedCertificateAsync(X509CertificateKeyIdPair issuerCAKeyCert,
            RSA publicKey, string subjectName, string applicationUri, string applicationName,
            IList<string> domainNames, ushort keySize, DateTime notBefore, DateTime notAfter,
            ushort hashSizeInBits, string extensionUrl) {

            if (issuerCAKeyCert?.Certificate == null) {
                throw new ArgumentNullException(nameof(issuerCAKeyCert), "Need a root cert.");
            }

            if (publicKey == null) {
                throw new ArgumentNullException(nameof(publicKey), "Need a public key.");
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
            request.CertificateExtensions.Add(
                X509ExtensionEx.BuildAuthorityKeyIdentifier(issuerCAKeyCert.Certificate));

            // Key Usage
            request.CertificateExtensions.Add(
                new X509KeyUsageExtension(
                    X509KeyUsageFlags.DigitalSignature | 
                    X509KeyUsageFlags.DataEncipherment |
                    X509KeyUsageFlags.NonRepudiation |
                    X509KeyUsageFlags.KeyEncipherment, true));

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
                    X509ExtensionEx.BuildX509AuthorityInformationAccess(new string[] {
                        PatchExtensionUrl(extensionUrl, issuerCAKeyCert.Certificate.SerialNumber)
                    }));
            }

            // Adjust validity to issuer cert
            if (notAfter > issuerCAKeyCert.Certificate.NotAfter) {
                notAfter = issuerCAKeyCert.Certificate.NotAfter;
            }
            if (notBefore < issuerCAKeyCert.Certificate.NotBefore) {
                notBefore = issuerCAKeyCert.Certificate.NotBefore;
            }

            var issuerSubjectName = issuerCAKeyCert.Certificate.SubjectName;
            var signatureGenerator = new SignatureGeneratorAdapter(_signer, issuerCAKeyCert);
            var signedCert = request.Create(issuerSubjectName, signatureGenerator, notBefore,
                notAfter, serialNumber);
            return Task.FromResult(signedCert);
        }

        /// <summary>
        /// Build the Subject Alternative name extension (for OPC UA application certs)
        /// </summary>
        /// <param name="applicationUri">The application Uri</param>
        /// <param name="domainNames">The domain names.
        /// DNS Hostnames, IPv4 or IPv6 addresses</param>
        public static X509Extension BuildSubjectAlternativeName(string applicationUri,
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
