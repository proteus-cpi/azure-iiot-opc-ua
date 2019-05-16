// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace Microsoft.Azure.IIoT.OpcUa.Vault.KeyVault {
    using Microsoft.Azure.IIoT.OpcUa.Vault.KeyVault.Models;
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Security.Cryptography;
    using System.Security.Cryptography.Asn1;
    using System.Security.Cryptography.X509Certificates;
    using System.Text;
    using System.Threading.Tasks;

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
            request.CertificateExtensions.Add(X509ExtensionEx.BuildAuthorityKeyIdentifier(
                subjectDN, serialNumber.Reverse().ToArray(), ski));

            request.CertificateExtensions.Add(new X509KeyUsageExtension(
                    X509KeyUsageFlags.DigitalSignature |
                    X509KeyUsageFlags.KeyCertSign |
                    X509KeyUsageFlags.CrlSign, true));
            if (extensionUrl != null) {
                // add CRL endpoint, if available
                request.CertificateExtensions.Add(X509ExtensionEx.BuildX509CRLDistributionPoints(
                    PatchExtensionUrl(extensionUrl, serialNumber)));
            }
            var key = new X509CertificateKeyIdPair {
                Certificate = null, // Root
                KeyIdentifier = signingKey
            };
            var issuerSubjectName = subjectDN;
            var signatureGenerator = new SignatureGeneratorAdapter(signer, key);
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
