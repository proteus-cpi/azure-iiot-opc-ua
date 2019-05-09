// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace Microsoft.Azure.IIoT.OpcUa.Registry.Models {
    using Newtonsoft.Json;

    /// <summary>
    /// Registry application status model
    /// </summary>
    public sealed class RegistryApplicationStatusModel {

        /// <summary>
        /// The state of the applications in the registry and the security database.
        /// </summary>
        public RegistryApplicationStatusType Status { get; set; }

        /// <summary>
        /// The current application information in the registry database.
        /// </summary>
        public ApplicationInfoModel Registry { get; set; }

        /// <summary>
        /// The application information in the security database.
        /// </summary>
        public ApplicationInfoModel Application { get; set; }
    }
}
