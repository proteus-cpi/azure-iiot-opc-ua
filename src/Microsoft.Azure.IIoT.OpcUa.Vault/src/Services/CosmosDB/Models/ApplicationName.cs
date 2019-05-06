// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace Microsoft.Azure.IIoT.OpcUa.Vault.CosmosDB.Models {
    using System;

    /// <summary>
    /// Application name
    /// </summary>
    [Serializable]
    public class ApplicationName {

        /// <summary>
        /// Locale
        /// </summary>
        public string Locale { get; set; }

        /// <summary>
        /// Text
        /// </summary>
        public string Text { get; set; }
    }
}
