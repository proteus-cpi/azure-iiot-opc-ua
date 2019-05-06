// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace Microsoft.Azure.IIoT.OpcUa.Vault.Models {
    using Microsoft.Azure.IIoT.OpcUa.Vault.CosmosDB.Models;

    /// <summary>
    /// Read request result
    /// </summary>
    public sealed class ReadRequestResultModel {

        /// <summary>
        /// Request
        /// </summary>
        public string RequestId { get; set; }

        /// <summary>
        /// Application id
        /// </summary>
        public string ApplicationId { get; set; }

        /// <summary>
        /// State
        /// </summary>
        public CertificateRequestState State { get; set; }

        /// <summary>
        /// Certificate group id
        /// </summary>
        public string CertificateGroupId { get; set; }

        /// <summary>
        /// Type id
        /// </summary>
        public string CertificateTypeId { get; set; }

        /// <summary>
        /// Signing request
        /// </summary>
        public bool SigningRequest { get; set; }

        /// <summary>
        /// Subject name
        /// </summary>
        public string SubjectName { get; set; }

        /// <summary>
        /// Domain names
        /// </summary>
        public string[] DomainNames { get; set; }

        /// <summary>
        /// Private key
        /// </summary>
        public string PrivateKeyFormat { get; set; }

        /// <summary>
        /// Create read request
        /// </summary>
        /// <param name="request"></param>
        public ReadRequestResultModel(CertificateRequestDocument request) {
            RequestId = request.RequestId.ToString();
            ApplicationId = request.ApplicationId;
            State = request.CertificateRequestState;
            CertificateGroupId = request.CertificateGroupId;
            CertificateTypeId = request.CertificateTypeId;
            SigningRequest = request.SigningRequest != null;
            SubjectName = request.SubjectName;
            DomainNames = request.DomainNames;
            PrivateKeyFormat = request.PrivateKeyFormat;
        }

        /// <summary>
        /// Create read request result
        /// </summary>
        /// <param name="requestId"></param>
        /// <param name="applicationId"></param>
        /// <param name="state"></param>
        /// <param name="certificateGroupId"></param>
        /// <param name="certificateTypeId"></param>
        /// <param name="certificateRequest"></param>
        /// <param name="subjectName"></param>
        /// <param name="domainNames"></param>
        /// <param name="privateKeyFormat"></param>
        public ReadRequestResultModel(string requestId, string applicationId,
            CertificateRequestState state, string certificateGroupId,
            string certificateTypeId, byte[] certificateRequest,
            string subjectName, string[] domainNames, string privateKeyFormat) {
            RequestId = requestId;
            ApplicationId = applicationId;
            State = state;
            CertificateGroupId = certificateGroupId;
            CertificateTypeId = certificateTypeId;
            SigningRequest = certificateRequest != null;
            SubjectName = subjectName;
            DomainNames = domainNames;
            PrivateKeyFormat = privateKeyFormat;
        }
    }
}

