// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace Microsoft.Azure.IIoT.OpcUa.Registry.Models {
    using System.Collections.Generic;

    /// <summary>
    /// Application query response
    /// </summary>
    public sealed class QueryApplicationsResultModel {

        /// <summary>
        /// Found applications
        /// </summary>
        public IList<ApplicationInfoModel> Applications { get; set; }

        /// <summary>
        /// Next page
        /// </summary>
        public string NextPageLink { get; set; }
    }
}