// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace Microsoft.Azure.IIoT.OpcUa.Vault.Services {
    using Microsoft.Azure.IIoT.OpcUa.Vault.CosmosDB;
    using Autofac;
    using Serilog;

    /// <summary>
    /// Helper to create app darabase for unit tests.
    /// </summary>
    public static class CosmosDBApplicationsDatabaseFactory {

        /// <summary>
        /// Create database
        /// </summary>
        /// <param name="scope"></param>
        /// <param name="config"></param>
        /// <param name="db"></param>
        /// <param name="logger"></param>
        /// <returns></returns>
        public static IApplicationsDatabase Create(ILifetimeScope scope,
            IVaultConfig config, IDocumentDBRepository db, ILogger logger) =>
            new CosmosDBApplicationsDatabase(scope, config, db, logger);
    }
}
