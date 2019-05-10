﻿// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace Microsoft.Azure.IIoT.OpcUa.Vault.Models {
    using Microsoft.Azure.IIoT.OpcUa.Vault.Services.KeyVault.Models;
    using System.Security.Cryptography.X509Certificates;

    /// <summary>
    /// Trust list model extensions
    /// </summary>
    public static class KeyVaultTrustListModelEx {

        /// <summary>
        /// Convert to service model
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        public static TrustListModel ToServiceModel(this KeyVaultTrustListModel model) {
            return new TrustListModel {
                GroupId = model.Group,
                IssuerCertificates = model.IssuerCertificates?.ToServiceModel(null),
                IssuerCrls = model.IssuerCrls.ToServiceModel(),
                NextPageLink = model.NextPageLink,
                TrustedCertificates = model.TrustedCertificates?.ToServiceModel(null),
                TrustedCrls = model.TrustedCrls.ToServiceModel()
            };
        }
    }
}