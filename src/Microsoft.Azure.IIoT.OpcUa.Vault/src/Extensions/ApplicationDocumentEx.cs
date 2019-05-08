// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------


namespace Microsoft.Azure.IIoT.OpcUa.Vault.CosmosDB.Models {
    using Microsoft.Azure.IIoT.OpcUa.Vault.Models;
    using System;
    using System.Linq;

    /// <summary>
    /// Application document extensions
    /// </summary>
    public static class ApplicationDocumentEx {

        /// <summary>
        /// Create model
        /// </summary>
        /// <param name="application"></param>
        public static ApplicationRecordModel ToServiceModel(this ApplicationDocument application) {
            return new ApplicationRecordModel {
                ApplicationId = application.ApplicationId,
                RecordId = application.ID,
                State = application.ApplicationState,
                ApplicationUri = application.ApplicationUri,
                ApplicationName = application.ApplicationName,
                ApplicationType = application.ApplicationType,
                LocalizedNames = application.ApplicationNames?.ToList(),
                ProductUri = application.ProductUri,
                DiscoveryUrls = application.DiscoveryUrls,
                Capabilities = application.ServerCapabilities,
                GatewayServerUri = application.GatewayServerUri,
                DiscoveryProfileUri = application.DiscoveryProfileUri,
                ApproveTime = application.ApproveTime,
                AuthorityId = application.AuthorityId,
                CreateTime = application.CreateTime,
                DeleteTime = application.DeleteTime,
                RegistryId = application.RegistryId,
                UpdateTime = application.UpdateTime
            };
        }

        /// <summary>
        /// Convert to service model
        /// </summary>
        /// <returns></returns>
        public static ApplicationDocument ToDocumentModel(this ApplicationRecordModel model) {
            return new ApplicationDocument {
                // ID and State are ignored, readonly
                ApplicationId = model.ApplicationId,
                ApplicationUri = model.ApplicationUri,
                ApplicationName = model.ApplicationName,
                ApplicationType = model.ApplicationType,
                ApplicationNames = model.LocalizedNames?.ToArray(),
                ProductUri = model.ProductUri,
                DiscoveryUrls = model.DiscoveryUrls?.ToArray(),
                ServerCapabilities = model.Capabilities,
                GatewayServerUri = model.GatewayServerUri,
                DiscoveryProfileUri = model.DiscoveryProfileUri,
                UpdateTime = model.UpdateTime,
                RegistryId = model.RegistryId,
                DeleteTime = model.DeleteTime,
                CreateTime = model.CreateTime,
                AuthorityId = model.AuthorityId,
                ApproveTime = model.ApproveTime,
                ApplicationState = model.State,
                ID = model.RecordId,
            };
        }
    }
}
