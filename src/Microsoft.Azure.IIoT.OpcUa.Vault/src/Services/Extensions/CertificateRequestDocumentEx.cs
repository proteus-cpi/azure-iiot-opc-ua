// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------


namespace Microsoft.Azure.IIoT.OpcUa.Vault.Models {
    using Microsoft.Azure.IIoT.OpcUa.Vault.Services.Registry.Models;
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
                CertificateTypeId = Enum.Parse<CertificateType>(document.CertificateTypeId),
                DomainNames = document.DomainNames?.ToList(),
                PrivateKeyFormat = Enum.Parse<PrivateKeyFormat>(document.PrivateKeyFormat),
                SigningRequest = document.SigningRequest != null,
                SubjectName = document.SubjectName,
                State = document.CertificateRequestState
            };
        }

        /// <summary>
        /// Create model
        /// </summary>
        /// <param name="document"></param>
        public static CertificateRequestDocument Clone(
            this CertificateRequestDocument document) {
            return new CertificateRequestDocument {
                RequestId = document.RequestId,
                ApplicationId = document.ApplicationId,
                CertificateGroupId = document.CertificateGroupId,
                CertificateTypeId = document.CertificateTypeId,
                DomainNames = document.DomainNames?.ToArray(),
                PrivateKeyFormat = document.PrivateKeyFormat,
                SigningRequest = document.SigningRequest.ToArray(),
                SubjectName = document.SubjectName,
                AcceptTime = document.AcceptTime,
                ApproveRejectTime = document.ApproveRejectTime,
                AuthorityId = document.AuthorityId,
                Certificate = document.Certificate,
                ClassType = document.ClassType,
                DeleteTime = document.DeleteTime,
                ETag = document.ETag,
                ID = document.ID,
                PrivateKeyPassword = document.PrivateKeyPassword,
                RequestTime = document.RequestTime,
                RevokeTime =document.RevokeTime,
                CertificateRequestState = document.CertificateRequestState
            };
        }
    }
}
