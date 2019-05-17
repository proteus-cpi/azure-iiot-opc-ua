// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace System.Security.Cryptography.X509Certificates {
    using Microsoft.Azure.IIoT.Crypto.BouncyCastle;
    using Microsoft.Azure.IIoT.OpcUa.Vault.Models;
    using Newtonsoft.Json.Linq;
    using Opc.Ua;
    using Org.BouncyCastle.Asn1.X509;
    using Org.BouncyCastle.Crypto;
    using Org.BouncyCastle.Crypto.Parameters;
    using Org.BouncyCastle.Math;
    using Org.BouncyCastle.Pkcs;
    using Org.BouncyCastle.Security;
    using Org.BouncyCastle.X509;
    using System.IO;
    using System.Linq;

    /// <summary>
    /// X509 cert extensions
    /// </summary>
    public static class X509Certificate2Ex {

        /// <summary>
        /// Get file name or return default
        /// </summary>
        /// <param name="cert"></param>
        /// <param name="defaultName"></param>
        /// <returns></returns>
        public static string GetFileNameOrDefault(this X509CertificateModel cert,
            string defaultName) {
            try {
                var dn = Utils.ParseDistinguishedName(cert.Subject);
                var prefix = dn
                    .FirstOrDefault(x => x.StartsWith("CN=",
                    StringComparison.OrdinalIgnoreCase)).Substring(3);
                return prefix + " [" + cert.Thumbprint + "]";
            }
            catch {
                return defaultName;
            }
        }

        /// <summary>
        /// Create certificate from cert
        /// </summary>
        /// <param name="certificate"></param>
        /// <param name="withCertificate"></param>
        public static X509CertificateModel ToServiceModel(this X509Certificate2 certificate,
            bool withCertificate = true) {
            return new X509CertificateModel {
                Certificate = withCertificate ? certificate.RawData : null,
                Thumbprint = certificate.Thumbprint,
                SerialNumber = certificate.SerialNumber,
                NotBefore = certificate.NotBefore,
                NotAfter = certificate.NotAfter,
                Subject = certificate.Subject
            };
        }

        /// <summary>
        /// Convert to framework model
        /// </summary>
        /// <returns></returns>
        public static X509Certificate2 ToStackModel(this X509CertificateModel model) {
            return new X509Certificate2(model.ToRawData());
        }

        /// <summary>
        /// Find subject key in certificate
        /// </summary>
        /// <param name="certificate"></param>
        /// <returns></returns>
        public static X509SubjectKeyIdentifierExtension FindSubjectKeyIdentifierExtension(
            this X509Certificate2 certificate) {
            foreach (var extension in certificate.Extensions) {
                if (extension is X509SubjectKeyIdentifierExtension subjectKeyExtension) {
                    return subjectKeyExtension;
                }
            }
            return null;
        }

        /// <summary>
        /// Find auth key
        /// </summary>
        /// <param name="certificate"></param>
        /// <returns></returns>
        public static X509AuthorityKeyIdentifierExtension FindAuthorityKeyIdentifier(
            this X509Certificate2 certificate) {
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
        /// Create a X509Certificate2 with a private key by combining
        /// the new certificate with a private key from an RSA key.
        /// </summary>
        public static X509Certificate2 CreateCertificateWithPrivateKey(
            this X509Certificate2 certificate, RSA privatekey) {
            using (var cfrg = new RandomGeneratorAdapter()) {
                var random = new SecureRandom(cfrg);
                var x509 = new X509CertificateParser().ReadCertificate(certificate.RawData);
                return CreateCertificateWithPrivateKey(x509, certificate.FriendlyName,
                    GetPrivateKeyParameter(privatekey), random);
            }
        }

#if !UNUSED
        /// <summary>
        /// Get public key parameters from a X509Certificate2
        /// </summary>
        public static RsaKeyParameters GetPublicKeyParameters(this X509Certificate2 certificate) {
            using (var rsa = certificate.GetRSAPublicKey()) {
                var rsaParams = rsa.ExportParameters(false);
                return new RsaKeyParameters(false,
                    new BigInteger(1, rsaParams.Modulus),
                    new BigInteger(1, rsaParams.Exponent));
            }
        }
#endif

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
        /// Create a X509Certificate2 with a private key by combining
        /// a bouncy castle X509Certificate and private key parameters.
        /// </summary>
        public static X509Certificate2 CreateCertificateWithPrivateKey(
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
        /// Get Raw data
        /// </summary>
        /// <returns></returns>
        public static byte[] ToRawData(this X509CertificateModel model) {
            const string certPemHeader = "-----BEGIN CERTIFICATE-----";
            const string certPemFooter = "-----END CERTIFICATE-----";
            if (model.Certificate == null) {
                throw new ArgumentNullException(nameof(model.Certificate));
            }
            switch (model.Certificate.Type) {
                case JTokenType.Bytes:
                    return (byte[])model.Certificate;
                case JTokenType.String:
                    var request = (string)model.Certificate;
                    if (request.Contains(certPemHeader,
                        StringComparison.OrdinalIgnoreCase)) {
                        var strippedCertificateRequest = request.Replace(
                            certPemHeader, "", StringComparison.OrdinalIgnoreCase);
                        strippedCertificateRequest = strippedCertificateRequest.Replace(
                            certPemFooter, "", StringComparison.OrdinalIgnoreCase);
                        return Convert.FromBase64String(strippedCertificateRequest);
                    }
                    return Convert.FromBase64String(request);
                default:
                    throw new ArgumentException(
                        "Bad certificate data", nameof(model.Certificate));
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
    }
}
