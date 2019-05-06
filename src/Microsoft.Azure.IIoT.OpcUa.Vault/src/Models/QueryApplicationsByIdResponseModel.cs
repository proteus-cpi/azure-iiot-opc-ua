// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT).
//  See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace Microsoft.Azure.IIoT.OpcUa.Vault.Models {
    using Microsoft.Azure.IIoT.OpcUa.Vault.CosmosDB.Models;
    using System;

    /// <summary>
    /// Query applications by id
    /// </summary>
    public sealed class QueryApplicationsByIdResponseModel {

        /// <summary>
        /// Applications
        /// </summary>
        public ApplicationDocument[] Applications { get; set; }

        /// <summary>
        /// Last counter reset
        /// </summary>
        public DateTime LastCounterResetTime { get; set; }

        /// <summary>
        /// Next record id
        /// </summary>
        public int NextRecordId { get; set; }

        /// <summary>
        /// Create model
        /// </summary>
        /// <param name="applications"></param>
        /// <param name="lastCounterResetTime"></param>
        /// <param name="nextRecordId"></param>
        public QueryApplicationsByIdResponseModel(
            ApplicationDocument[] applications,
            DateTime lastCounterResetTime,
            uint nextRecordId
            ) {
            Applications = applications;
            LastCounterResetTime = lastCounterResetTime;
            NextRecordId = (int)nextRecordId;
        }
    }
}

