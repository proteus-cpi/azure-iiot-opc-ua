// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------


namespace Microsoft.Azure.IIoT.OpcUa.Vault.Models {
    using Opc.Ua.Gds.Server;

    /// <summary>
    /// Cert group configuration extensions
    /// </summary>
    public static class CertificateGroupConfigurationEx {

        /// <summary>
        /// Convert to gds model
        /// </summary>
        /// <returns></returns>
        public static CertificateGroupConfiguration ToGdsServerModel(
            this CertificateGroupConfigurationModel model) {
            return new CertificateGroupConfiguration {
                Id = model.Id,
                CertificateType = model.CertificateType,
                SubjectName = model.SubjectName,
                BaseStorePath = "/" + model.Id.ToLower(),
                DefaultCertificateHashSize = model.DefaultCertificateHashSize,
                DefaultCertificateKeySize = model.DefaultCertificateKeySize,
                DefaultCertificateLifetime = model.DefaultCertificateLifetime,
                CACertificateHashSize = model.IssuerCACertificateHashSize,
                CACertificateKeySize = model.IssuerCACertificateKeySize,
                CACertificateLifetime = model.IssuerCACertificateLifetime
            };
        }
    }
}
