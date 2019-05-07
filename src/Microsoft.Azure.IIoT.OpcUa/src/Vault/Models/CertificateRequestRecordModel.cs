// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace Microsoft.Azure.IIoT.OpcUa.Vault.Models {
    using System.Collections.Generic;

    /// <summary>
    /// Certificate request record model
    /// </summary>
    public sealed class CertificateRequestRecordModel {

        /// <summary>
        /// Request id
        /// </summary>
        public string RequestId { get; set; }

        /// <summary>
        /// Application id
        /// </summary>
        public string ApplicationId { get; set; }

        /// <summary>
        /// Request state
        /// </summary>
        public CertificateRequestState State { get; set; }

        /// <summary>
        /// Certificate group
        /// </summary>
        public string CertificateGroupId { get; set; }

        /// <summary>
        /// Type
        /// </summary>
        public string CertificateTypeId { get; set; }

        /// <summary>
        /// Is Signing request
        /// </summary>
        public bool SigningRequest { get; set; }

        /// <summary>
        /// Subject
        /// </summary>
        public string SubjectName { get; set; }

        /// <summary>
        /// Domain names
        /// </summary>
        public IList<string> DomainNames { get; set; }

        /// <summary>
        /// Private key format to return
        /// </summary>
        public string PrivateKeyFormat { get; set; }
    }
}
