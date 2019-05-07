// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace Microsoft.Azure.IIoT.OpcUa.Vault.Models {
    using System;

    /// <summary>
    /// Signing request
    /// </summary>
    public static class CreateSigningRequestModelEx {

        /// <summary>
        /// Convert back to service model
        /// </summary>
        /// <returns></returns>
        public static byte[] ToBuffer(this CreateSigningRequestModel model) {
            const string certRequestPemHeader = "-----BEGIN CERTIFICATE REQUEST-----";
            const string certRequestPemFooter = "-----END CERTIFICATE REQUEST-----";
            if (model.CertificateRequest != null) {
                if (model.CertificateRequest.Contains(certRequestPemHeader,
                    StringComparison.OrdinalIgnoreCase)) {
                    var strippedCertificateRequest = model.CertificateRequest.Replace(
                        certRequestPemHeader, "", StringComparison.OrdinalIgnoreCase);
                    strippedCertificateRequest = strippedCertificateRequest.Replace(
                        certRequestPemFooter, "", StringComparison.OrdinalIgnoreCase);
                    return Convert.FromBase64String(strippedCertificateRequest);
                }
                return Convert.FromBase64String(model.CertificateRequest);
            }
            return null;
        }
    }
}
