// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace System.Security.Cryptography.X509Certificates {
    using Opc.Ua;
    using Org.BouncyCastle.Asn1;
    using Org.BouncyCastle.Asn1.Pkcs;
    using Org.BouncyCastle.Asn1.X509;
    using Org.BouncyCastle.Pkcs;

    /// <summary>
    /// Certificate request info extensions
    /// </summary>
    public static class CertificationRequestInfoEx {

        /// <summary>
        /// Convert buffer to request info
        /// </summary>
        /// <param name="certificateRequest"></param>
        /// <returns></returns>
        public static CertificationRequestInfo ToCertificationRequestInfo(
            this byte[] certificateRequest) {
            var pkcs10CertificationRequest = new Pkcs10CertificationRequest(
                certificateRequest);
            if (!pkcs10CertificationRequest.Verify()) {
                throw new ArgumentException("CSR signature invalid.",
                    nameof(certificateRequest));
            }
            return pkcs10CertificationRequest.GetCertificationRequestInfo();
        }

        /// <summary>
        /// Get alt name extension from info
        /// </summary>
        /// <param name="info"></param>
        /// <returns></returns>
        public static X509SubjectAltNameExtension GetAltNameExtensionFromCSRInfo(
            this CertificationRequestInfo info) {
            try {
                foreach (Asn1Encodable attribute in info.Attributes) {
                    var sequence = Asn1Sequence.GetInstance(attribute.ToAsn1Object());
                    var oid = DerObjectIdentifier.GetInstance(sequence[0].ToAsn1Object());
                    if (oid.Equals(PkcsObjectIdentifiers.Pkcs9AtExtensionRequest)) {
                        var extensionInstance = Asn1Set.GetInstance(sequence[1]);
                        var extensionSequence = Asn1Sequence.GetInstance(extensionInstance[0]);
                        var extensions = X509Extensions.GetInstance(extensionSequence);
                        var extension = extensions.GetExtension(X509Extensions.SubjectAlternativeName);
                        var asnEncodedAltNameExtension = new AsnEncodedData(
                            X509Extensions.SubjectAlternativeName.ToString(),
                            extension.Value.GetOctets());
                        var altNameExtension = new X509SubjectAltNameExtension(
                            asnEncodedAltNameExtension, extension.IsCritical);
                        return altNameExtension;
                    }
                }
            }
            catch {
                throw new ServiceResultException(StatusCodes.BadInvalidArgument,
                    "CSR altNameExtension invalid.");
            }
            return null;
        }

    }
}
