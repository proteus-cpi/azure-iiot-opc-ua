// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace Microsoft.Azure.IIoT.OpcUa.Vault.Models {
    using Opc.Ua;
    using System;

    /// <summary>
    /// A X509 certificate revocation list extensions
    /// </summary>
    public static class X509CrlEx {

        /// <summary>
        /// Create crl
        /// </summary>
        /// <param name="crl"></param>
        public static X509CrlModel ToServiceModel(this X509CRL crl) {
            return new X509CrlModel {
                RawData = crl.RawData,
                Issuer = crl.Issuer
            };
        }

        /// <summary>
        /// Convert to service model
        /// </summary>
        /// <returns></returns>
        public static X509CRL ToStackModel(this X509CrlModel model) {
            return new X509CRL(model.RawData);
        }
    }
}
