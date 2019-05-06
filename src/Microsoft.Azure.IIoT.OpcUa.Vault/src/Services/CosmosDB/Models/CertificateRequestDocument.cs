// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace Microsoft.Azure.IIoT.OpcUa.Vault.CosmosDB.Models {
    using Microsoft.Azure.IIoT.OpcUa.Vault.Models;
    using Newtonsoft.Json;
    using System;

    /// <summary>
    /// Certificate request document in cosmos db
    /// </summary>
    [Serializable]
    public class CertificateRequestDocument {

        /// <summary>
        /// Document id
        /// </summary>
        [JsonProperty(PropertyName = "id")]
        public Guid RequestId { get; set; }

        /// <summary>
        /// Etag
        /// </summary>
        [JsonProperty(PropertyName = "_etag")]
        public string ETag { get; set; }

        /// <summary>
        /// Document type
        /// </summary>
        public string ClassType { get; set; } = ClassTypeName;

        /// <summary>
        /// Numeric index
        /// </summary>
        public int ID { get; set; }

        /// <summary>
        /// Application id
        /// </summary>
        public string ApplicationId { get; set; }

        /// <summary>
        /// Request state
        /// </summary>
        public CertificateRequestState CertificateRequestState { get; set; }

        /// <summary>
        /// Group id
        /// </summary>
        public string CertificateGroupId { get; set; }

        /// <summary>
        /// Type id
        /// </summary>
        public string CertificateTypeId { get; set; }

        /// <summary>
        /// Signing request
        /// </summary>
        public byte[] SigningRequest { get; set; }

        /// <summary>
        /// Subject name
        /// </summary>
        public string SubjectName { get; set; }

        /// <summary>
        /// Domain name
        /// </summary>
        public string[] DomainNames { get; set; }

        /// <summary>
        /// Private key format
        /// </summary>
        public string PrivateKeyFormat { get; set; }

        /// <summary>
        /// Key password
        /// </summary>
        public string PrivateKeyPassword { get; set; }

        /// <summary>
        /// Authority id
        /// </summary>
        public string AuthorityId { get; set; }

        /// <summary>
        /// Certificate
        /// </summary>
        public byte[] Certificate { get; set; }

        /// <summary>
        /// Request time
        /// </summary>
        public DateTime? RequestTime { get; set; }

        /// <summary>
        /// Approve or reject time
        /// </summary>
        public DateTime? ApproveRejectTime { get; set; }

        /// <summary>
        /// Accept time
        /// </summary>
        public DateTime? AcceptTime { get; set; }

        /// <summary>
        /// Delete time
        /// </summary>
        public DateTime? DeleteTime { get; set; }

        /// <summary>
        /// Revoke time
        /// </summary>
        public DateTime? RevokeTime { get; set; }

        /// <inheritdoc/>

        public static readonly string ClassTypeName = "CertificateRequest";
    }
}
