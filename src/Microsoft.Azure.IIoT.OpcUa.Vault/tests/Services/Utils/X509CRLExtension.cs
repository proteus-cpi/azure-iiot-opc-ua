// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace Microsoft.Azure.IIoT.OpcUa.Vault.Tests {
    using Microsoft.Azure.IIoT.OpcUa.Vault.Models;
    using System;
    using System.Collections.Generic;

    public static class X509CRLExtension {
        internal static void AddRange<T>(this IList<T> list, IEnumerable<T> items) {
            if (list == null) {
                throw new ArgumentNullException(nameof(list));
            }

            if (items == null) {
                throw new ArgumentNullException(nameof(items));
            }

            if (list is List<T>) {
                ((List<T>)list).AddRange(items);
            }
            else {
                foreach (var item in items) {
                    list.Add(item);
                }
            }
        }

        internal static void AddRange(this KeyVaultTrustListModel list, KeyVaultTrustListModel items) {
            if (list == null) {
                throw new ArgumentNullException(nameof(list));
            }

            if (items == null) {
                throw new ArgumentNullException(nameof(items));
            }

            list.TrustedCertificates.AddRange(items.TrustedCertificates);
            list.TrustedCrls.AddRange(items.TrustedCrls);
            list.IssuerCertificates.AddRange(items.IssuerCertificates);
            list.IssuerCrls.AddRange(items.IssuerCrls);
        }

    }

}
