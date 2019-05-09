// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------


namespace Microsoft.Azure.IIoT.OpcUa.Vault.CosmosDB.Models {
    using Microsoft.Azure.IIoT.OpcUa.Registry.Models;
    using System;
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
                Capabilities = document.ServerCapabilities?.Split(',').ToHashSet(),
                GatewayServerUri = document.GatewayServerUri,
                DiscoveryProfileUri = document.DiscoveryProfileUri,
                Approved = ToServiceModel(document.ApproveTime, document.ApproveAuthorityId),
                Created = ToServiceModel(document.CreateTime, document.CreateAuthorityId),
                Deleted = ToServiceModel(document.DeleteTime, document.DeleteAuthorityId),
                Updated = ToServiceModel(document.UpdateTime, document.UpdateAuthorityId),
            };
        }

        /// <summary>
        /// Convert to service model
        /// </summary>
        /// <returns></returns>
        public static ApplicationDocument ToDocumentModel(this ApplicationInfoModel model) {
            return new ApplicationDocument {
                ID = model.RecordId ?? 0,
                ApplicationState = model.State,
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
                UpdateTime = model.Updated?.Time,
                DeleteTime = model.Deleted?.Time,
                CreateTime = model.Created?.Time,
                ApproveTime = model.Approved?.Time,
                UpdateAuthorityId = model.Updated?.AuthorityId,
                DeleteAuthorityId = model.Deleted?.AuthorityId,
                CreateAuthorityId = model.Created?.AuthorityId,
                ApproveAuthorityId = model.Approved?.AuthorityId,
            };
        }

        /// <summary>
        /// Registry registry operation model from fields
        /// </summary>
        /// <param name="time"></param>
        /// <param name="authorityId"></param>
        /// <returns></returns>
        private static RegistryOperationModel ToServiceModel(DateTime? time,
            string authorityId) {
            if (time == null) {
                return null;
            }
            return new RegistryOperationModel {
                AuthorityId = string.IsNullOrEmpty(authorityId) ?
                    "Unknown" : authorityId,
                Time = time.Value
            };
        }
    }
}
