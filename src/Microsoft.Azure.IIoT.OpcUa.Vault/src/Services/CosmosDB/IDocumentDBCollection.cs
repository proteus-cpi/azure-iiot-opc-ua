// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------


namespace Microsoft.Azure.IIoT.OpcUa.Vault.CosmosDB {
    using Microsoft.Azure.Documents;
    using System;
    using System.Collections.Generic;
    using System.Linq.Expressions;
    using System.Threading.Tasks;

    /// <summary>
    /// Document collection
    /// </summary>
    /// <typeparam name="T"></typeparam>
    public interface IDocumentDBCollection<T> where T : class {

        /// <summary>
        /// Collection
        /// </summary>
        DocumentCollection Collection { get; }

        /// <summary>
        /// Create if not exist
        /// </summary>
        /// <returns></returns>
        Task CreateCollectionIfNotExistsAsync();

        /// <summary>
        /// Create document
        /// </summary>
        /// <param name="item"></param>
        /// <returns></returns>
        Task<Document> CreateAsync(T item);

        /// <summary>
        /// Delete
        /// </summary>
        /// <param name="id"></param>
        /// <returns></returns>
        Task DeleteAsync(string id);

        /// <summary>
        /// Get
        /// </summary>
        /// <param name="id"></param>
        /// <returns></returns>
        Task<T> GetAsync(string id);

        /// <summary>
        /// Get
        /// </summary>
        /// <param name="predicate"></param>
        /// <returns></returns>
        Task<IEnumerable<T>> GetAsync(
            Expression<Func<T, bool>> predicate);

        /// <summary>
        /// Get page
        /// </summary>
        /// <param name="predicate"></param>
        /// <param name="continuationToken"></param>
        /// <param name="maxItemCount"></param>
        /// <returns></returns>
        Task<(string, IEnumerable<T>)> GetPageAsync(
            Expression<Func<T, bool>> predicate,
            string continuationToken, int? maxItemCount);

        /// <summary>
        /// Get
        /// </summary>
        /// <param name="sqlQuerySpec"></param>
        /// <returns></returns>
        Task<IEnumerable<T>> GetAsync(SqlQuerySpec sqlQuerySpec);

        /// <summary>
        /// Get page
        /// </summary>
        /// <param name="sqlQuerySpec"></param>
        /// <param name="continuationToken"></param>
        /// <param name="maxItemCount"></param>
        /// <returns></returns>
        Task<(string, IEnumerable<T>)> GetPageAsync(
            SqlQuerySpec sqlQuerySpec,
            string continuationToken, int? maxItemCount);

        /// <summary>
        /// Update
        /// </summary>
        /// <param name="id"></param>
        /// <param name="item"></param>
        /// <param name="eTag"></param>
        /// <returns></returns>
        Task<Document> UpdateAsync(string id, T item,
            string eTag);
    }
}
