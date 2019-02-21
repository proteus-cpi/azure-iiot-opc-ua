// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace Microsoft.Azure.IIoT.OpcUa.Twin {
    using Microsoft.Azure.IIoT.OpcUa.Twin.Models;
    using System.Threading.Tasks;

    /// <summary>
    /// Historian services
    /// </summary>
    /// <typeparam name="T"></typeparam>
    public interface IHistorianServices<T> { 

        /// <summary>
        /// Read node history
        /// </summary>
        /// <param name="endpoint"></param>
        /// <param name="request"></param>
        /// <returns></returns>
        Task<HistoryReadResultModel> HistoryReadAsync(T endpoint,
            HistoryReadRequestModel request);

        /// <summary>
        /// Read node history continuation
        /// </summary>
        /// <param name="endpoint"></param>
        /// <param name="request"></param>
        /// <returns></returns>
        Task<HistoryReadNextResultModel> HistoryReadNextAsync(T endpoint,
            HistoryReadNextRequestModel request);

        /// <summary>
        /// Update node history
        /// </summary>
        /// <param name="endpoint"></param>
        /// <param name="request"></param>
        /// <returns></returns>
        Task<HistoryUpdateResultModel> HistoryUpdateAsync(T endpoint,
            HistoryUpdateRequestModel request);
    }
}
