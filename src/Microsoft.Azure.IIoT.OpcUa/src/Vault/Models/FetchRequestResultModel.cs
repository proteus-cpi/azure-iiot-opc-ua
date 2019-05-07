// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace Microsoft.Azure.IIoT.OpcUa.Vault.Models {

    /// <summary>
    /// Fetch request result
    /// </summary>
    public sealed class FetchRequestResultModel {

        /// <summary>
        /// Request state
        /// </summary>
        public CertificateRequestState State { get; set; }

        /// <summary>
        /// Application id
        /// </summary>
        public string ApplicationId { get; set; }

        /// <summary>
        /// Request id
        /// </summary>
        public string RequestId { get; set; }

        /// <summary>
        /// Certificate group
        /// </summary>
        public string CertificateGroupId { get; set; }

        /// <summary>
        /// Certificate type
        /// </summary>
        public string CertificateTypeId { get; set; }

        /// <summary>
        /// Signed cert
        /// </summary>
        public byte[] SignedCertificate { get; set; }

        /// <summary>
        /// Format
        /// </summary>
        public string PrivateKeyFormat { get; set; }

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

