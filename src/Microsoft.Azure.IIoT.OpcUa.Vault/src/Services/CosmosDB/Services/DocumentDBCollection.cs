// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace Microsoft.Azure.IIoT.OpcUa.Vault.CosmosDB.Services {
    using Microsoft.Azure.Documents;
    using Microsoft.Azure.Documents.Client;
    using Microsoft.Azure.Documents.Linq;
    using Microsoft.Azure.IIoT.Exceptions;
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Linq.Expressions;
    using System.Threading.Tasks;

    /// <summary>
    /// Cosmos db based document collection
    /// </summary>
    /// <typeparam name="T"></typeparam>
    public class DocumentDBCollection<T> : IDocumentDBCollection<T> where T : class {

        /// <inheritdoc/>
        public DocumentCollection Collection { get; private set; }

        /// <summary>
        /// Create collection
        /// </summary>
        /// <param name="db"></param>
        public DocumentDBCollection(IDocumentDBRepository db) :
            this(db, typeof(T).Name) {
        }

        /// <summary>
        /// Create collection
        /// </summary>
        /// <param name="db"></param>
        /// <param name="collectionId"></param>
        public DocumentDBCollection(IDocumentDBRepository db, string collectionId) {
            if (string.IsNullOrEmpty(collectionId)) {
                throw new ArgumentNullException(nameof(collectionId),
                    "collectionId must be set");
            }
            _collectionId = collectionId;
            _db = db ?? throw new ArgumentNullException(nameof(db));
        }

        /// <inheritdoc/>
        public async Task<T> GetAsync(string id) {
            if (string.IsNullOrEmpty(id)) {
                throw new ArgumentNullException(nameof(id));
            }
            try {
                Document document = await _db.Client.ReadDocumentAsync(
                    UriFactory.CreateDocumentUri(_db.DatabaseId, _collectionId, id));
                return (T)(dynamic)document;
            }
            catch (DocumentClientException e) {
                if (e.StatusCode == System.Net.HttpStatusCode.NotFound) {
                    throw new ResourceNotFoundException("A record with the specified id does not exist.");
                }
                else {
                    throw e;
                }
            }
        }

        /// <inheritdoc/>
        public async Task<IEnumerable<T>> GetAsync(Expression<Func<T, bool>> predicate) {
            var feedOptions = new FeedOptions { MaxItemCount = -1 };
            var query = _db.Client.CreateDocumentQuery<T>(
                UriFactory.CreateDocumentCollectionUri(_db.DatabaseId, _collectionId),
                feedOptions)
            .Where(predicate)
            .AsDocumentQuery();

            var results = new List<T>();
            while (query.HasMoreResults) {
                results.AddRange(await query.ExecuteNextAsync<T>());
            }

            return results;
        }

        /// <inheritdoc/>
        public async Task<IEnumerable<T>> GetAsync(SqlQuerySpec sqlQuerySpec) {
            var feedOptions = new FeedOptions { MaxItemCount = -1 };
            var query = _db.Client.CreateDocumentQuery<T>(
                UriFactory.CreateDocumentCollectionUri(_db.DatabaseId, _collectionId),
                sqlQuerySpec,
                feedOptions)
            .AsDocumentQuery();

            var results = new List<T>();
            while (query.HasMoreResults) {
                results.AddRange(await query.ExecuteNextAsync<T>());
            }
            return results;
        }

        /// <inheritdoc/>
        public async Task<(string, IEnumerable<T>)> GetPageAsync(
            Expression<Func<T, bool>> predicate,
            string continuationToken,
            int? maxItemCount
            ) {
            var feedOptions = new FeedOptions {
                MaxItemCount = maxItemCount ?? DefaultMaxItemCount,
                RequestContinuation = continuationToken
            };
            var query = _db.Client.CreateDocumentQuery<T>(
                UriFactory.CreateDocumentCollectionUri(_db.DatabaseId, _collectionId),
                feedOptions)
            .Where(predicate)
            .AsDocumentQuery();

            var results = new List<T>();
            FeedResponse<T> queryResult = null;
            while (query.HasMoreResults) {
                queryResult = await query.ExecuteNextAsync<T>();
                results.AddRange(queryResult);
                if (queryResult.ResponseContinuation != null) {
                    break;
                }
            }

            return (queryResult.ResponseContinuation, results);
        }

        /// <inheritdoc/>
        public async Task<(string, IEnumerable<T>)> GetPageAsync(
            SqlQuerySpec sqlQuerySpec,
            string continuationToken,
            int? maxItemCount
            ) {
            var feedOptions = new FeedOptions {
                MaxItemCount = maxItemCount ?? DefaultMaxItemCount,
                RequestContinuation = continuationToken
            };
            var query = _db.Client.CreateDocumentQuery<T>(
                UriFactory.CreateDocumentCollectionUri(_db.DatabaseId, _collectionId),
                sqlQuerySpec,
                feedOptions)
            .AsDocumentQuery();

            var results = new List<T>();
            FeedResponse<T> queryResult = null;
            while (query.HasMoreResults) {
                queryResult = await query.ExecuteNextAsync<T>();
                results.AddRange(queryResult);
                if (queryResult.ResponseContinuation != null) {
                    break;
                }
            }

            return (queryResult.ResponseContinuation, results);
        }

        /// <inheritdoc/>
        public async Task<Document> CreateAsync(T item) {
            return await _db.Client.CreateDocumentAsync(
                UriFactory.CreateDocumentCollectionUri(_db.DatabaseId, _collectionId), item);
        }

        /// <inheritdoc/>
        public async Task<Document> UpdateAsync(string id, T item, string eTag) {
            if (string.IsNullOrEmpty(id)) {
                throw new ArgumentNullException(nameof(id));
            }
            var ac = new RequestOptions {
                AccessCondition = new AccessCondition {
                    Condition = eTag,
                    Type = AccessConditionType.IfMatch
                }
            };

            return await _db.Client.ReplaceDocumentAsync(
                UriFactory.CreateDocumentUri(_db.DatabaseId, _collectionId, id), item, ac);
        }

        /// <inheritdoc/>
        public Task DeleteAsync(string id) {
            if (string.IsNullOrEmpty(id)) {
                Task.FromException(new ArgumentNullException(nameof(id)));
            }
            return _db.Client.DeleteDocumentAsync(UriFactory.CreateDocumentUri(
                _db.DatabaseId, _collectionId, id));
        }

        /// <inheritdoc/>
        public async Task CreateCollectionIfNotExistsAsync() {
            try {
                await _db.CreateRepositoryIfNotExistsAsync();
                Collection = await _db.Client.ReadDocumentCollectionAsync(
                    UriFactory.CreateDocumentCollectionUri(_db.DatabaseId, _collectionId));
            }
            catch (DocumentClientException e) {
                if (e.StatusCode == System.Net.HttpStatusCode.NotFound) {
                    Collection = await _db.Client.CreateDocumentCollectionAsync(
                        UriFactory.CreateDatabaseUri(_db.DatabaseId),
                        new DocumentCollection {
                            Id = _collectionId,
                            UniqueKeyPolicy = _db.UniqueKeyPolicy
                        },
                        new RequestOptions { OfferThroughput = kRequestLevelLowest });
                }
                else {
                    throw;
                }
            }
        }

        /// <inheritdoc/>
        public const int DefaultMaxItemCount = 10;
        private readonly IDocumentDBRepository _db;
        private readonly string _collectionId;
        private const int kRequestLevelLowest = 400;
    }
}
