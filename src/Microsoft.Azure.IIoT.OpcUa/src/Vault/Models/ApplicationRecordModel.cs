// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace Microsoft.Azure.IIoT.OpcUa.Vault.Models {
    using Microsoft.Azure.IIoT.OpcUa.Registry.Models;
    using System;
    using System.Collections.Generic;

    /// <summary>
    /// Record service model
    /// </summary>
    public sealed class ApplicationRecordModel {

        /// <summary>
        /// Application id
        /// </summary>
        public string ApplicationId { get; set; }

        /// <summary>
        /// Application uri
        /// </summary>
        public string ApplicationUri { get; set; }

        /// <summary>
        /// Application name
        /// </summary>
        public string ApplicationName { get; set; }

        /// <summary>
        /// Application type
        /// </summary>
        public ApplicationType ApplicationType { get; set; }

        /// <summary>
        /// Application names
        /// </summary>
        public IList<ApplicationNameModel> ApplicationNames { get; set; }

        /// <summary>
        /// Product uri
        /// </summary>
        public string ProductUri { get; set; }

        /// <summary>
        /// Service caps
        /// </summary>
        public string ServerCapabilities { get; set; }

        /// <summary>
        /// Gateway server uri
        /// </summary>
        public string GatewayServerUri { get; set; }

        /// <summary>
        /// Discovery urls
        /// </summary>
        public IList<string> DiscoveryUrls { get; set; }

        /// <summary>
        /// Discovery profile uri
        /// </summary>
        public string DiscoveryProfileUri { get; set; }





        /// <summary>
        /// State
        /// </summary>
        public ApplicationState State { get; set; }

        /// <summary>
        /// Record id
        /// </summary>
        public int RecordId { get; set; }

        /// <summary>
        /// Authority
        /// </summary>
        public string AuthorityId { get; set; }

        /// <summary>
        /// Device Registry id - reflects id of what was discovered.
        /// </summary>
        public string RegistryId { get; set; }

        /// <summary>
        /// Create time
        /// </summary>
        public DateTime? CreateTime { get; set; }

        /// <summary>
        /// Approval time
        /// </summary>
        public DateTime? ApproveTime { get; set; }

        /// <summary>
        /// Update time
        /// </summary>
        public DateTime? UpdateTime { get; set; }

        /// <summary>
        /// Delete time
        /// </summary>
        public DateTime? DeleteTime { get; set; }
    }
}
