// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace Microsoft.Azure.IIoT.OpcUa.Vault.Models {
    using System.Collections.Generic;

    /// <summary>
    /// New key pair request
    /// </summary>
    public sealed class NewKeyPairRequestModel {

        /// <summary>
        /// Application id
        /// </summary>
        public string ApplicationId { get; set; }

        /// <summary>
        /// Certificate group
        /// </summary>
        public string CertificateGroupId { get; set; }

        /// <summary>
        /// Type
        /// </summary>
        public CertificateType CertificateTypeId { get; set; }

        /// <summary>
        /// Subject name
        /// </summary>
        public string SubjectName { get; set; }

        /// <summary>
        /// Domain names
        /// </summary>
        public List<string> DomainNames { get; set; }

        /// <summary>
        /// Format
        /// </summary>
        public PrivateKeyFormat PrivateKeyFormat { get; set; }

        /// <summary>
        /// Password
        /// </summary>
        public string PrivateKeyPassword { get; set; }
    }
}
