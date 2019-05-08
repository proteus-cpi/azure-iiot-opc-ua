// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace Microsoft.Azure.IIoT.OpcUa.Vault.Models {
    using Newtonsoft.Json;
    using System.Collections.Generic;

    /// <summary>
    /// Query result model
    /// </summary>
    public sealed class CertificateRequestQueryResultModel {

        /// <summary>
        /// The query result.
        /// </summary>
        public IList<CertificateRequestRecordModel> Requests { get; set; }

        /// <summary>
        /// Link to the next page of results.
        /// </summary>
        public string NextPageLink { get; set; }
    }
}
