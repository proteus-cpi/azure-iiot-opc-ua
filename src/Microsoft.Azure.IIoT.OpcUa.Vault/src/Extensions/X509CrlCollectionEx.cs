// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace Microsoft.Azure.IIoT.OpcUa.Vault.Models {
    using System.Collections.Generic;
    using System.Linq;
    using System.Security.Cryptography.X509Certificates;

    /// <summary>
    /// Crl collection model
    /// </summary>
    public static class X509CrlCollectionEx {

        /// <summary>
        /// Create collection model
        /// </summary>
        /// <param name="crls"></param>
        /// <param name="nextPageLink"></param>
        public static X509CrlCollectionModel ToServiceModel(this IEnumerable<X509Crl2> crls,
            string nextPageLink = null) {
            return new X509CrlCollectionModel {
                Chain = crls
                    .Select(crl => crl.ToServiceModel())
                    .ToList(),
                NextPageLink = nextPageLink
            };
        }

        /// <summary>
        /// Create collection
        /// </summary>
        /// <param name="crls"></param>
        public static IList<X509Crl2> ToStackModel(this X509CrlCollectionModel crls) {
            return crls.Chain
                .Select(c => c.ToStackModel())
                .ToList();
        }
    }
}
