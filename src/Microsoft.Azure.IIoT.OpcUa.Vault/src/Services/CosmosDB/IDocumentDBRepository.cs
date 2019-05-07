// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace Microsoft.Azure.IIoT.OpcUa.Vault.CosmosDB {
    using Microsoft.Azure.Documents;
    using Microsoft.Azure.Documents.Client;
    using System.Threading.Tasks;

    /// <summary>
    /// Document repository interface
    /// </summary>
    public interface IDocumentDBRepository {

        /// <TODO/>
        Task CreateRepositoryIfNotExistsAsync();

        /// <summary>
        /// The Unique Key Policy used when a new collection is created.
        /// </summary>
        UniqueKeyPolicy UniqueKeyPolicy { get; }

        /// <summary>
        /// The document client used by collections.
        /// </summary>
        DocumentClient Client { get; }

        /// <summary>
        /// The name of the DocumentDB repository.
        /// </summary>
        string DatabaseId { get; }
    }
}
