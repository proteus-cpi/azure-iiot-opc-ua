// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace Microsoft.Azure.IIoT.OpcUa.Vault.Models {

    /// <summary>
    /// Certificate group create model
    /// </summary>
    public sealed class CertificateGroupCreateRequestModel {

        /// <summary>
        /// The new name of the certificate group
        /// </summary>
        public string Name { get; set; }

        /// <summary>
        /// The certificate type for the new group as specified 
        /// in the OPC UA spec 1.04.
        /// </summary>
        public CertificateType CertificateType { get; set; }

        /// <summary>
        /// The subject of the new Issuer CA certificate
        /// </summary>
        public string SubjectName { get; set; }
    }
}
