// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------


namespace Microsoft.Azure.IIoT.OpcUa.Vault.CosmosDB.Models {
    using Microsoft.Azure.IIoT.OpcUa.Registry.Models;
    using System.Linq;

    /// <summary>
    /// Application document extensions
    /// </summary>
    public static class ApplicationDocumentEx {

        /// <summary>
        /// Create model
        /// </summary>
        /// <param name="document"></param>
        public static ApplicationInfoModel ToServiceModel(this ApplicationDocument document) {
            return new ApplicationInfoModel {
                ApplicationId = document.ApplicationId,
                RecordId = document.ID,
                State = document.ApplicationState,
                ApplicationUri = document.ApplicationUri,
                ApplicationName = document.ApplicationName,
                ApplicationType = document.ApplicationType,
                LocalizedNames = document.ApplicationNames?
                    .ToDictionary(n => n.Locale, n => n.Name),
                ProductUri = document.ProductUri,
                DiscoveryUrls = document.DiscoveryUrls.ToHashSetSafe(),
                Capabilities = document.ServerCapabilities,
                GatewayServerUri = document.GatewayServerUri,
                DiscoveryProfileUri = document.DiscoveryProfileUri,
                ApproveTime = document.ApproveTime,
                AuthorityId = document.AuthorityId,
                CreateTime = document.CreateTime,
                DeleteTime = document.DeleteTime,
                UpdateTime = document.UpdateTime
            };
        }

        /// <summary>
        /// Convert to service model
        /// </summary>
        /// <returns></returns>
        public static ApplicationDocument ToDocumentModel(this ApplicationInfoModel model) {
            return new ApplicationDocument {
                ApplicationId = model.ApplicationId,
                ApplicationUri = model.ApplicationUri,
                ApplicationName = model.ApplicationName,
                ApplicationType = model.ApplicationType,
                ApplicationNames = model.LocalizedNames?
                    .Select(kv => new ApplicationDocument.LocalizedText {
                        Locale = kv.Key,
                        Name = kv.Value
                    })
                    .ToArray(),
                ProductUri = model.ProductUri,
                DiscoveryUrls = model.DiscoveryUrls?.ToArray(),
                ServerCapabilities = model.Capabilities.Aggregate((x, y) => $"{x},{y}"),
                GatewayServerUri = model.GatewayServerUri,
                DiscoveryProfileUri = model.DiscoveryProfileUri,
                UpdateTime = model.UpdateTime,
                DeleteTime = model.DeleteTime,
                CreateTime = model.CreateTime,
                AuthorityId = model.AuthorityId,
                ApproveTime = model.ApproveTime,
                ApplicationState = model.State,
                ID = model.RecordId ?? 0,
            };
        }
    }
}
