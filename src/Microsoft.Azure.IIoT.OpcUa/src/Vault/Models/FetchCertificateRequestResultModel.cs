// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace Microsoft.Azure.IIoT.OpcUa.Vault.Models {

    /// <summary>
    /// Fetch request result
    /// </summary>
    public sealed class FetchCertificateRequestResultModel {

        /// <summary>
        /// Certificate type
        /// </summary>
        public CertificateRequestRecordModel Request { get; set; }

        /// <summary>
        /// Signed cert
        /// </summary>
        public byte[] SignedCertificate { get; set; }

        /// <summary>
        /// Private key
        /// </summary>
        public byte[] PrivateKey { get; set; }

        /// <summary>
        /// Authority
        /// </summary>
        public string AuthorityId { get; set; }
    }
}

