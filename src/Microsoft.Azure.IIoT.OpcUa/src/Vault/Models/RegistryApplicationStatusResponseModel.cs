// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace Microsoft.Azure.IIoT.OpcUa.Vault.Models {
    using Newtonsoft.Json;
    using System.Collections.Generic;

    /// <summary>
    /// Registry application status response
    /// </summary>
    public sealed class RegistryApplicationStatusResponseModel {

        /// <summary>
        /// Applications
        /// </summary>
        public IList<RegistryApplicationStatusModel> Applications { get; set; }

        /// <summary>
        /// Next link
        /// </summary>
        public string NextPageLink { get; set; }
    }
}
