// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace Microsoft.Azure.IIoT.OpcUa.Vault.Services.CosmosDB.Services {
    using Autofac;
    using Microsoft.Azure.Documents;
    using Microsoft.Azure.Documents.Client;
    using Microsoft.Azure.IIoT.OpcUa.Registry;
    using Microsoft.Azure.IIoT.Storage.CosmosDb;
    using Microsoft.Azure.IIoT.Utils;
    using Newtonsoft.Json;
    using System;
    using System.Collections.Generic;
    using System.Collections.ObjectModel;

    /// <summary>
    /// Cosmos db document repository
    /// </summary>
    public class DocumentDBRepository : IDocumentDBRepository {

        /// <inheritdoc/>
        public UniqueKeyPolicy UniqueKeyPolicy { get; }

        /// <inheritdoc/>
        public DocumentClient Client { get; }

        /// <inheritdoc/>
        public string DatabaseId { get; }

        /// <summary>
        /// Create repository
        /// </summary>
        /// <param name="config"></param>
        public DocumentDBRepository(ICosmosDbConfig config) {
            DatabaseId = "OpcVault"; // config.DatabaseName;
            UniqueKeyPolicy = new UniqueKeyPolicy {
                UniqueKeys = new Collection<UniqueKey>()
            };
            var cs = ConnectionString.Parse(config.DbConnectionString);
            Client = new DocumentClient(new Uri(cs.Endpoint),
                cs.SharedAccessKey, SerializerSettings());
            Client.CreateDatabaseIfNotExistsAsync(new Database {
                Id = DatabaseId
            }).Wait();
        }

        /// <summary>
        /// Used settings
        /// </summary>
        /// <returns></returns>
        private JsonSerializerSettings SerializerSettings() {
            return new JsonSerializerSettings {
                TypeNameHandling = TypeNameHandling.None,
                DateFormatHandling = DateFormatHandling.IsoDateFormat,
                Converters = new List<JsonConverter> {
                    new Newtonsoft.Json.Converters.StringEnumConverter {
                        NamingStrategy = null,
                        AllowIntegerValues = true
                    }
                }
            };
        }
    }
}
