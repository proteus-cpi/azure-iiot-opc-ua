// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace Microsoft.Azure.IIoT.OpcUa.Registry.Models {
    using System.Collections.Generic;

    /// <summary>
    /// Query applications
    /// </summary>
    public sealed class QueryApplicationsRequestModel {

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
        public QueryApplicationType ApplicationType { get; set; }

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
        public ApplicationStateMask? ApplicationState { get; set; }
    }
}
