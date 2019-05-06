// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT).
//  See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace Microsoft.Azure.IIoT.OpcUa.Vault.Models {
    using Microsoft.Azure.IIoT.OpcUa.Vault.CosmosDB.Models;

    /// <summary>
    /// Query applications response model
    /// </summary>
    public sealed class QueryApplicationsResponseModel {

        /// <summary>
        /// Applications
        /// </summary>
        public ApplicationDocument[] Applications { get; set; }

        /// <summary>
        /// Next page link
        /// </summary>
        public string NextPageLink { get; set; }

        /// <summary>
        /// Create response
        /// </summary>
        /// <param name="applications"></param>
        /// <param name="nextPageLink"></param>
        public QueryApplicationsResponseModel(ApplicationDocument[] applications,
            string nextPageLink) {
            Applications = applications;
            NextPageLink = nextPageLink;
        }
    }
}

