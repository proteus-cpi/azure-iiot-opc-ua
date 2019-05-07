﻿// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace Microsoft.Azure.IIoT.OpcUa.Vault.Tests {
    using Microsoft.Azure.IIoT.OpcUa.Vault.Models;
    using System;
    using System.Collections.Generic;

    public static class X509CRLExtension {


        internal static void AddRange(this X509CertificateCollectionModel list,
            X509CertificateCollectionModel items) {
            if (list == null || items == null) {
                return;
            }
            foreach (var item in items.Chain) {
                list.Chain.Add(item);
            }
        }

        internal static void AddRange(this X509CrlCollectionModel list,
            X509CrlCollectionModel items) {
            if (list == null || items == null) {
                return;
            }
            foreach (var item in items.Chain) {
                list.Chain.Add(item);
            }
        }

        internal static void AddRange(this TrustListModel list, TrustListModel items) {
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
