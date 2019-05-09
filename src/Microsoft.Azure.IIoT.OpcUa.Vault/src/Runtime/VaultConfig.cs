// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace Microsoft.Azure.IIoT.OpcUa.Vault.Runtime {
    using Microsoft.Azure.IIoT.OpcUa.Vault;
    using Microsoft.Azure.IIoT.Utils;
    using Microsoft.Extensions.Configuration;

    /// <inheritdoc/>
    public class VaultConfig : ConfigBase, IVaultConfig {

        /// <summary>
        /// Vault configuration
        /// </summary>
        private const string kOpcVault_ServiceHostKey = "OpcVault:ServiceHost";
        private const string kOpcVault_ApplicationsAutoApproveKey = "OpcVault:ApplicationsAutoApprove";

        /// <inheritdoc/>
        public string ServiceHost => GetStringOrDefault(
            kOpcVault_ServiceHostKey);
        /// <inheritdoc/>
        public bool ApplicationsAutoApprove => GetBoolOrDefault(kOpcVault_ApplicationsAutoApproveKey,
            GetBoolOrDefault("OPC_VAULT_AUTOAPPROVE", true));

        /// <summary>
        /// Key Vault configuration
        /// </summary>
        private const string kOpcVault_KeyVaultBaseUrlKey = "OpcVault:KeyVaultBaseUrl";
        private const string kOpcVault_KeyVaultResourceIdKey = "OpcVault:KeyVaultResourceId";
        private const string kOpcVault_KeyVaultIsHsmKey = "OpcVault:KeyVaultIsHsm";

        /// <inheritdoc/>
        public string KeyVaultBaseUrl => GetStringOrDefault(kOpcVault_KeyVaultBaseUrlKey,
            GetStringOrDefault("OPC_VAULT_KEYVAULT_URI",
                GetStringOrDefault("PCS_KEYVAULT_CONFIGURATION_URI"))).Trim();
        /// <inheritdoc/>
        public string KeyVaultResourceId => GetStringOrDefault(kOpcVault_KeyVaultResourceIdKey,
            GetStringOrDefault("OPC_VAULT_KEYVAULT_RESOURCE_ID",
                "https://vault.azure.net")).Trim();
        /// <inheritdoc/>
        public bool KeyVaultIsHsm => GetBoolOrDefault(
            kOpcVault_KeyVaultIsHsmKey, true);

        /// <summary>
        /// Cosmos db configuration
        /// </summary>
        private const string kOpcVault_CosmosDBConnectionStringKey = "OpcVault:CosmosDBConnectionString";
        private const string kOpcVault_CosmosDBCollectionKey = "OpcVault:CosmosDBCollection";
        private const string kOpcVault_CosmosDBDatabaseKey = "OpcVault:CosmosDBDatabase";

        /// <inheritdoc/>
        public string CosmosDBConnectionString => GetStringOrDefault(kOpcVault_CosmosDBConnectionStringKey,
            GetStringOrDefault("OPC_VAULT_COSMOSDB_CONNSTRING",
                GetStringOrDefault("PCS_TELEMETRY_DOCUMENTDB_CONNSTRING",
                GetStringOrDefault("_DB_CS", null))));
        /// <inheritdoc/>
        public string CosmosDBDatabase => GetStringOrDefault(kOpcVault_CosmosDBDatabaseKey,
            GetStringOrDefault("OPC_VAULT_COSMOSDB_DBNAME", "OpcVault")).Trim();
        /// <inheritdoc/>
        public string CollectionName => GetStringOrDefault(kOpcVault_CosmosDBCollectionKey,
            GetStringOrDefault("OPC_VAULT_COSMOSDB_COLLNAME", "AppsAndCertRequests")).Trim();

        /// <summary>
        /// Configuration constructor
        /// </summary>
        /// <param name="configuration"></param>
        public VaultConfig(IConfigurationRoot configuration) :
            base(configuration) {
        }
    }
}
