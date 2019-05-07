// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------


namespace Microsoft.Azure.IIoT.OpcUa.Vault.CosmosDB.Models {
    using Microsoft.Azure.IIoT.OpcUa.Vault.Models;
    using System;
    using System.Linq;

    /// <summary>
    /// Cert request document extensions
    /// </summary>
    public static class CertificateRequestDocumentEx {

        /// <summary>
        /// Create model
        /// </summary>
        /// <param name="application"></param>
        public static CertificateRequestRecordModel ToServiceModel(
            this CertificateRequestDocument application) {
            return new CertificateRequestRecordModel {
                RequestId = application.RequestId != Guid.Empty ?
                    application.RequestId.ToString() : null,
                ApplicationId = application.ApplicationId,
                CertificateGroupId = application.CertificateGroupId,
                CertificateTypeId = application.CertificateTypeId,
                DomainNames = application.DomainNames?.ToList(),
                PrivateKeyFormat = application.PrivateKeyFormat,
                SigningRequest = application.SigningRequest != null,
                SubjectName = application.SubjectName,
            };
        }
    }
}
