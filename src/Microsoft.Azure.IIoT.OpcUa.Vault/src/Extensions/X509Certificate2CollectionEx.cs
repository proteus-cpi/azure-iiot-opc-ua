// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace Microsoft.Azure.IIoT.OpcUa.Vault.Models {
    using System.Linq;
    using System.Collections.Generic;
    using System.Security.Cryptography.X509Certificates;

    /// <summary>
    /// Certificate collection extensions
    /// </summary>
    public static class X509Certificate2CollectionEx {

        /// <summary>
        /// Create collection
        /// </summary>
        /// <param name="certificateCollection"></param>
        /// <param name="nextPageLink"></param>
        public static X509CertificateCollectionModel ToServiceModel(
            this X509Certificate2Collection certificateCollection, string nextPageLink) {
            var chain = new List<X509CertificateModel>();
            foreach (var cert in certificateCollection) {
                var certApiModel = cert.ToServiceModel();
                chain.Add(certApiModel);
            }
            return new X509CertificateCollectionModel {
                NextPageLink = nextPageLink,
                Chain = chain
            };
        }

        /// <summary>
        /// Create collection
        /// </summary>
        /// <param name="certificateCollection"></param>
        public static X509Certificate2Collection ToStackModel(
            this X509CertificateCollectionModel certificateCollection) {
            return new X509Certificate2Collection(certificateCollection.Chain
                .Select(c=> c.ToStackModel()).ToArray());
        }
    }
}
