// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace Microsoft.Azure.IIoT.OpcUa.Twin.Models {
    using Newtonsoft.Json.Linq;

    /// <summary>
    /// Request node history update
    /// </summary>
    public class HistoryUpdateRequestModel {

        /// <summary>
        /// Node to update 
        /// </summary>
        public string NodeId { get; set; }

        /// <summary>
        /// An optional path from NodeId instance to
        /// an actual node.
        /// </summary>
        public string[] BrowsePath { get; set; }

        /// <summary>
        /// The HistoryUpdateDetailsType extension object
        /// encoded as json Variant and containing the tunneled
        /// update request for the Historian server. The value
        /// is updated at edge using above node address.
        /// </summary>
        public JToken Details { get; set; }

        /// <summary>
        /// Optional header
        /// </summary>
        public RequestHeaderModel Header { get; set; }
    }
}
