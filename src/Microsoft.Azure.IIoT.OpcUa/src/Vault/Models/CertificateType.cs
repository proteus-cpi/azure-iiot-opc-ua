// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace Microsoft.Azure.IIoT.OpcUa.Vault.Models {
    using Newtonsoft.Json;
    using Newtonsoft.Json.Converters;

    /// <summary>
    /// Certificate types
    /// </summary>
    [JsonConverter(typeof(StringEnumConverter))]
    public enum CertificateType {

        /// <summary>
        /// Application certificate
        /// </summary>
        ApplicationInstanceCertificateType,

        /// <summary>
        /// Https certificate type
        /// </summary>
        HttpsCertificateType,

        /// <summary>
        /// User credential certificate type
        /// </summary>
        UserCredentialCertificateType,
    }
}
