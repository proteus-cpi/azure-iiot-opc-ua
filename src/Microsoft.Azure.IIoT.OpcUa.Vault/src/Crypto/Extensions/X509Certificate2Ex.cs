// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace System.Security.Cryptography.X509Certificates {
    using Microsoft.Azure.IIoT.OpcUa.Vault.KeyVault;
    using Org.BouncyCastle.Asn1.X509;
    using Org.BouncyCastle.Crypto;
    using Org.BouncyCastle.Crypto.Parameters;
    using Org.BouncyCastle.Math;
    using Org.BouncyCastle.Pkcs;
    using Org.BouncyCastle.Security;
    using Org.BouncyCastle.X509;
    using System.IO;

    /// <summary>
    /// X509 cert extensions
    /// </summary>
    public static class X509Certificate2Ex2 {

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

        /// <summary>
        /// Get the serial number from a certificate as BigInteger.
        /// </summary>
        public static BigInteger GetSerialNumberAsBigInteger(this X509Certificate2 certificate) {
            var serialNumber = certificate.GetSerialNumber();
            Array.Reverse(serialNumber);
            return new BigInteger(1, serialNumber);
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
    }
}
