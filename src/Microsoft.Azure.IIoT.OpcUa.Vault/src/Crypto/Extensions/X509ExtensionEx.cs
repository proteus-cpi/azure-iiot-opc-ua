// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace System.Security.Cryptography.X509Certificates {
    using System.Collections.Generic;
    using System.Linq;
    using System.Net;
    using System.Security.Cryptography.Asn1;

    /// <summary>
    /// X509 extension extensions
    /// </summary>
    public static class X509ExtensionEx {

        /// <summary>
        /// Build the CRL Distribution Point extension.
        /// </summary>
        /// <param name="distributionPoint">The CRL distribution point</param>
        public static X509Extension BuildX509CRLDistributionPoints(string distributionPoint) {
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
        public static X509Extension BuildAuthorityKeyIdentifier(X500DistinguishedName issuerName,
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
        /// Build the Authority Key Identifier from an Issuer CA certificate.
        /// </summary>
        /// <param name="issuerCaCertificate">The issuer CA certificate</param>
        public static X509Extension BuildAuthorityKeyIdentifier(X509Certificate2 issuerCaCertificate) {
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
        public static X509Extension BuildX509AuthorityInformationAccess(string[] caIssuerUrls,
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

    }
}
