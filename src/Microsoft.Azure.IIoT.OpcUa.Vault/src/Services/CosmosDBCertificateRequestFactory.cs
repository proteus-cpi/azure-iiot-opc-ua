// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace Microsoft.Azure.IIoT.OpcUa.Vault.Services {
    using Microsoft.Azure.IIoT.OpcUa.Vault.CosmosDB;
    using Serilog;

    /// <summary>
    /// Certificate request factory
    /// </summary>
    public static class CosmosDBCertificateRequestFactory {

        /// <summary>
        /// Create request
        /// </summary>
        /// <param name="database"></param>
        /// <param name="certificateGroup"></param>
        /// <param name="config"></param>
        /// <param name="db"></param>
        /// <param name="logger"></param>
        /// <returns></returns>
        public static ICertificateRequest Create(IApplicationsDatabase database,
            ICertificateGroup certificateGroup, IVaultConfig config,
            IDocumentDBRepository db, ILogger logger) {
            return new CosmosDBCertificateRequest(database, certificateGroup, config, db, logger);
        }
    }
}
