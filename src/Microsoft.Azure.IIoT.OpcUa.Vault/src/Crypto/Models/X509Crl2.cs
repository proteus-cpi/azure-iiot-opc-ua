// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace System.Security.Cryptography.X509Certificates {
    using System;
    using Microsoft.Azure.IIoT.OpcUa.Vault.KeyVault;
    using Org.BouncyCastle.X509;

    /// <summary>
    /// Represents a crl in lieu of .net having one.
    /// </summary>
    public sealed class X509Crl2 {

        /// <summary>
        /// The subject name of the Issuer for the CRL.
        /// </summary>
        public string Issuer { get; }

        /// <summary>
        /// When the CRL was last updated.
        /// </summary>
        public DateTime UpdateTime { get; }

        /// <summary>
        /// When the CRL is due for its next update.
        /// </summary>
        public DateTime NextUpdateTime { get; }

        /// <summary>
        /// The raw data for the CRL.
        /// </summary>
        public byte[] RawData { get; }

        /// <summary>
        /// Loads a CRL from a memory buffer.
        /// </summary>
        public X509Crl2(byte[] crl) {
            RawData = crl;

            _crl = new X509CrlParser().ReadCrl(crl);

            UpdateTime = _crl.ThisUpdate;
            NextUpdateTime = _crl.NextUpdate == null ?
                DateTime.MinValue : _crl.NextUpdate.Value;

            Issuer = FixUpIssuer(_crl.IssuerDN.ToString());
        }

        /// <summary>
        /// Verifies the signature on the CRL.
        /// </summary>
        /// <param name="issuer"></param>
        public void Validate(X509Certificate2 issuer) {
            var bccert = new X509CertificateParser().ReadCertificate(issuer.RawData);
            _crl.Verify(bccert.GetPublicKey());
        }

        /// <summary>
        /// Verifies the signature on the CRL.
        /// </summary>
        /// <param name="issuer"></param>
        /// <returns></returns>
        public bool HasValidSignature(X509Certificate2 issuer) {
            try {
                Validate(issuer);
                return true;
            }
            catch (Exception) {
                return false;
            }
        }

        /// <summary>
        /// Returns true the certificate is in the CRL.
        /// </summary>
        public bool IsRevoked(X509Certificate2 issuer, X509Certificate2 certificate) {
            // check that the issuer matches.
            if (issuer == null || !CertUtils.CompareDistinguishedName(certificate.Issuer, issuer.Subject)) {
                throw new ArgumentException("Certificate was not created by the CRL issuer.");
            }

            var bccert = new X509CertificateParser().ReadCertificate(certificate.RawData);
            return _crl.IsRevoked(bccert);
        }

        /// <summary>
        /// Helper to make issuer match System.Security conventions
        /// </summary>
        /// <param name="issuerDN"></param>
        /// <returns></returns>
        private static string FixUpIssuer(string issuerDN) {
            // replace state ST= with S= 
            issuerDN = issuerDN.Replace("ST=", "S=");
            // reverse DN order 
            var issuerList = CertUtils.ParseDistinguishedName(issuerDN);
            issuerList.Reverse();
            return string.Join(", ", issuerList);
        }

        private readonly X509Crl _crl;
    }
}
