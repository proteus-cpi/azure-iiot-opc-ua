// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace Microsoft.Azure.IIoT.OpcUa.Vault.Models {
    using Newtonsoft.Json;
    using System.Collections.Generic;

    /// <summary>
    /// Query by id
    /// </summary>
    public sealed class QueryApplicationsByIdRequestModel {

        /// <summary>
        /// Application name
        /// </summary>
        public string ApplicationName { get; set; }

        /// <summary>
        /// Application uri
        /// </summary>
        public string ApplicationUri { get; set; }

        /// <summary>
        /// Application type
        /// </summary>
        public QueryApplicationType? ApplicationType { get; set; }

        /// <summary>
        /// Product uri
        /// </summary>
        public string ProductUri { get; set; }

        /// <summary>
        /// Server capabilities
        /// </summary>
        public IList<string> ServerCapabilities { get; set; }

        /// <summary>
        /// Application state
        /// </summary>
        public QueryApplicationState? ApplicationState { get; set; }

        /// <summary>
        /// Optional starting record id
        /// </summary>
        public uint? StartingRecordId { get; set; }

        /// <summary>
        /// Optional max records to return
        /// </summary>
        public uint? MaxRecordsToReturn { get; set; }
    }
}
