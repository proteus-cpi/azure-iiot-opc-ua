// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace Microsoft.Azure.IIoT.OpcUa.Vault.Models {
    using Newtonsoft.Json;
    using Newtonsoft.Json.Converters;

    /// <summary>
    /// The certificate request states.
    /// </summary>
    [JsonConverter(typeof(StringEnumConverter))]
    public enum CertificateRequestState {

        /// <summary>
        /// The request is new.
        /// </summary>
        New,

        /// <summary>
        /// The request was approved.
        /// </summary>
        Approved,

        /// <summary>
        /// The request was rejected.
        /// </summary>
        Rejected,

        /// <summary>
        /// The requests was accepted.
        /// </summary>
        Accepted,

        /// <summary>
        /// The request was deleted.
        /// </summary>
        Deleted,

        /// <summary>
        /// The requests was revoked.
        /// </summary>
        Revoked,

        /// <summary>
        /// The request was removed.
        /// </summary>
        Removed
    }
}

