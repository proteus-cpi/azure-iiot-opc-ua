// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace Microsoft.Azure.IIoT.OpcUa.Vault.Models {
    using System.Collections.Generic;

    /// <summary>
    /// Certificate collection
    /// </summary>
    public sealed class X509CertificateCollectionModel {

        /// <summary>
        /// Chain
        /// </summary>
        public List<X509CertificateModel> Chain { get; set; }

        /// <summary>
        /// Next link
        /// </summary>
        public string NextPageLink { get; set; }
    }
}
