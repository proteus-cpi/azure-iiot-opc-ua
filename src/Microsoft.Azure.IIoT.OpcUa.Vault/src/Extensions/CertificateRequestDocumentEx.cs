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
        /// <param name="document"></param>
        public static CertificateRequestRecordModel ToServiceModel(
            this CertificateRequestDocument document) {
            return new CertificateRequestRecordModel {
                RequestId = document.RequestId,
                ApplicationId = document.ApplicationId,
                CertificateGroupId = document.CertificateGroupId,
                CertificateTypeId = document.CertificateTypeId,
                DomainNames = document.DomainNames?.ToList(),
                PrivateKeyFormat = document.PrivateKeyFormat,
                SigningRequest = document.SigningRequest != null,
                SubjectName = document.SubjectName,
                State = document.CertificateRequestState
            };
        }
    }
}
