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
                ApplicationId = application.ApplicationId != Guid.Empty ?
                application.ApplicationId.ToString() : null,
                RecordId = application.Index,
                State = application.ApplicationState,
                ApplicationUri = application.ApplicationUri,
                ApplicationName = application.ApplicationName,
                ApplicationType = application.ApplicationType,
                ApplicationNames = application.ApplicationNames.ToList(),
                ProductUri = application.ProductUri,
                DiscoveryUrls = application.DiscoveryUrls,
                ServerCapabilities = application.ServerCapabilities,
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
                ApplicationId = model.ApplicationId != null ? new Guid(model.ApplicationId) : Guid.Empty,
                ApplicationUri = model.ApplicationUri,
                ApplicationName = model.ApplicationName,
                ApplicationType = model.ApplicationType,
                ApplicationNames = model.ApplicationNames.ToArray(),
                ProductUri = model.ProductUri,
                DiscoveryUrls = model.DiscoveryUrls?.ToArray(),
                ServerCapabilities = model.ServerCapabilities,
                GatewayServerUri = model.GatewayServerUri,
                DiscoveryProfileUri = model.DiscoveryProfileUri,
                UpdateTime = model.UpdateTime,
                RegistryId = model.RegistryId,
                DeleteTime = model.DeleteTime,
                CreateTime = model.CreateTime,
                AuthorityId = model.AuthorityId,
                ApproveTime = model.ApproveTime,
                ApplicationState = model.State,
                Index = model.RecordId,
            };
        }
    }
}
