// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace Microsoft.Azure.IIoT.OpcUa.Vault.Models {
    using Newtonsoft.Json.Linq;

    /// <summary>
    /// Signing request
    /// </summary>
    public sealed class SigningRequestModel {

        /// <summary>
        /// Application id
        /// </summary>
        public string ApplicationId { get; set; }

        /// <summary>
        /// Certificate group id
        /// </summary>
        public string CertificateGroupId { get; set; }

        /// <summary>
        /// Type
        /// </summary>
        public CertificateType CertificateTypeId { get; set; }

        /// <summary>
        /// Request buffer or PEM formated signing request
        /// </summary>
        public JToken CertificateRequest { get; set; }
    }
}
