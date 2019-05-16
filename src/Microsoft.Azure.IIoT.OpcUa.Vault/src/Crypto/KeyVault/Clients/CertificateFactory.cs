// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace Microsoft.Azure.IIoT.OpcUa.Vault.KeyVault {
    using Microsoft.Azure.IIoT.OpcUa.Vault.KeyVault.Models;
    using Org.BouncyCastle.Asn1;
    using Org.BouncyCastle.Asn1.X509;
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
    public static class CertificateFactory2 {

        /// <summary>
        /// Creates a self signed certificate
        /// </summary>
        /// <param name="subjectName"></param>
        /// <param name="keySize"></param>
        /// <param name="notBefore"></param>
        /// <param name="notAfter"></param>
        /// <param name="hashSizeInBits"></param>
        /// <param name="publicKey"></param>
        /// <param name="signer"></param>
        /// <param name="signingKey"></param>
        /// <param name="extensionUrl"></param>
        /// <returns></returns>
        public static Task<X509Certificate2> CreateSignedRootCertificateAsync(string subjectName,
            ushort keySize, DateTime notBefore, DateTime notAfter, ushort hashSizeInBits,
            RSA publicKey, IDigestSigner signer, string signingKey, string extensionUrl = null) {

            if (publicKey == null) {
                throw new NotSupportedException("Need a public key.");
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
            var subjectDN = SetSuitableDefaults(subjectName, ref keySize);

            var request = new CertificateRequest(subjectDN, publicKey,
                CertUtils.GetRSAHashAlgorithmName(hashSizeInBits), RSASignaturePadding.Pkcs1);

            // Basic constraints
            request.CertificateExtensions.Add(
                new X509BasicConstraintsExtension(true, true, 0, true)); // Self signed

            // Subject Key Identifier
            var ski = new X509SubjectKeyIdentifierExtension(
                request.PublicKey,
                X509SubjectKeyIdentifierHashAlgorithm.Sha1,
                false);
            request.CertificateExtensions.Add(ski);

            // Authority Key Identifier
            request.CertificateExtensions.Add(
                BuildAuthorityKeyIdentifier(subjectDN, serialNumber.Reverse().ToArray(), ski));

            request.CertificateExtensions.Add(new X509KeyUsageExtension(
                    X509KeyUsageFlags.DigitalSignature |
                    X509KeyUsageFlags.KeyCertSign |
                    X509KeyUsageFlags.CrlSign, true));
            if (extensionUrl != null) {
                // add CRL endpoint, if available
                request.CertificateExtensions.Add(BuildX509CRLDistributionPoints(
                    PatchExtensionUrl(extensionUrl, serialNumber)));
            }
            var key = new X509CertificateKeyIdPair {
                Certificate = null, // Root
                KeyIdentifier = signingKey
            };
            var issuerSubjectName = subjectDN;
            var signatureGenerator = new SignatureGenerator(signer, key);
            var signedCert = request.Create(issuerSubjectName, signatureGenerator, notBefore,
                notAfter, serialNumber);
            return Task.FromResult(signedCert);
        }

        /// <summary>
        /// Sets the parameters to suitable defaults.
        /// </summary>
        private static X500DistinguishedName SetSuitableDefaults(string subjectName, 
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
                subjectNameEntries = CertUtils.ParseDistinguishedName(subjectName);
                // enforce proper formatting for the subject name string
                subjectName = string.Join(", ", subjectNameEntries);
            }

            // remove special characters from name.
            var buffer = new StringBuilder();
            if (!subjectName.Contains("CN=")) {
                subjectName = "CN=" + subjectName;
            }
            return new X500DistinguishedName(subjectName);
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
