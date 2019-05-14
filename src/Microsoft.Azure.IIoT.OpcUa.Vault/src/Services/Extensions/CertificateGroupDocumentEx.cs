// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace Microsoft.Azure.IIoT.OpcUa.Vault.Models {
    using Microsoft.Azure.IIoT.OpcUa.Vault.Services.Models;
    using System;
    using System.Linq;

    /// <summary>
    /// Certificate group extensions
    /// </summary>
    public static class CertificateGroupDocumentEx {

        /// <summary>
        /// Create model
        /// </summary>
        /// <param name="document"></param>
        public static CertificateGroupInfoModel ToServiceModel(
            this CertificateGroupDocument document) {
            return new CertificateGroupInfoModel {
                Id = document.GroupId,
                DefaultCertificateHashSize = document.DefaultCertificateHashSize,
                DefaultCertificateKeySize = document.DefaultCertificateKeySize,
                DefaultCertificateLifetime = document.DefaultCertificateLifetime,
                IssuerCAAuthorityInformationAccess = document.IssuerCAAuthorityInformationAccess,
                IssuerCACertificateHashSize = document.IssuerCACertificateHashSize,
                IssuerCACertificateKeySize = document.IssuerCACertificateKeySize,
                IssuerCACertificateLifetime = document.IssuerCACertificateLifetime,
                IssuerCACrlDistributionPoint = document.IssuerCACrlDistributionPoint,
                SubjectName = document.SubjectName,
                CertificateType = Enum.Parse<CertificateType>(document.CertificateType)
            };
        }

        /// <summary>
        /// Convert to service model
        /// </summary>
        /// <returns></returns>
        public static CertificateGroupDocument ToDocumentModel(
            this CertificateGroupInfoModel model) {
            var document = new CertificateGroupDocument {
                GroupId = model.Id,
                DefaultCertificateHashSize = model.DefaultCertificateHashSize,
                DefaultCertificateKeySize = model.DefaultCertificateKeySize,
                DefaultCertificateLifetime = model.DefaultCertificateLifetime,
                IssuerCAAuthorityInformationAccess = model.IssuerCAAuthorityInformationAccess,
                IssuerCACertificateHashSize = model.IssuerCACertificateHashSize,
                IssuerCACertificateKeySize = model.IssuerCACertificateKeySize,
                IssuerCACertificateLifetime = model.IssuerCACertificateLifetime,
                IssuerCACrlDistributionPoint = model.IssuerCACrlDistributionPoint,
                SubjectName = model.SubjectName,
                Name = null,
                CertificateType = model.CertificateType.ToString()
            };
            // document.Validate();
            return document;
        }

        /// <summary>
        /// Convert to service model
        /// </summary>
        /// <returns></returns>
        public static CertificateGroupDocument Clone(this CertificateGroupDocument model) {
            return new CertificateGroupDocument {
                GroupId = model.GroupId,
                DefaultCertificateHashSize = model.DefaultCertificateHashSize,
                DefaultCertificateKeySize = model.DefaultCertificateKeySize,
                DefaultCertificateLifetime = model.DefaultCertificateLifetime,
                IssuerCAAuthorityInformationAccess = model.IssuerCAAuthorityInformationAccess,
                IssuerCACertificateHashSize = model.IssuerCACertificateHashSize,
                IssuerCACertificateKeySize = model.IssuerCACertificateKeySize,
                IssuerCACertificateLifetime = model.IssuerCACertificateLifetime,
                IssuerCACrlDistributionPoint = model.IssuerCACrlDistributionPoint,
                SubjectName = model.SubjectName,
                Name = model.Name,
                CertificateType = model.CertificateType,
                ETag = model.ETag,
                ClassType = model.ClassType
            };
        }
    }
}
