// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace Microsoft.Azure.IIoT.OpcUa.Graph.Models {
    using Gremlin.Net.CosmosDb.Structure;
    using Newtonsoft.Json;

    /// <summary>
    /// Method node vertex
    /// </summary>
    [Label(AddressSpaceElementNames.Method)]
    public class MethodNodeVertexModel : NodeVertexModel {

        /// <summary>
        /// If method node class, whether method can be called.
        /// </summary>
        [JsonProperty(PropertyName = "executable")]
        public bool? Executable { get; set; }
    }
}