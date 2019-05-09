// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace Microsoft.Azure.IIoT.OpcUa.Registry.Models {
    using System;
    using System.Collections.Generic;

    /// <summary>
    /// Create response
    /// </summary>
    public sealed class QueryApplicationsByIdResultModel {

        /// <summary>
        /// Applications found
        /// </summary>
        public IList<ApplicationInfoModel> Applications { get; set; }

        /// <summary>
        /// Last counter reset
        /// </summary>
        public DateTime LastCounterResetTime { get; set; }

        /// <summary>
        /// Next record id
        /// </summary>
        public uint NextRecordId { get; set; }
    }
}
