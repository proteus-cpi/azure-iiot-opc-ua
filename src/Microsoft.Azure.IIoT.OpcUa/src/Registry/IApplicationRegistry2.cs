// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace Microsoft.Azure.IIoT.OpcUa.Registry {
    using Microsoft.Azure.IIoT.OpcUa.Registry.Models;
    using System.Threading.Tasks;

    /// <summary>
    /// Application Database interface.
    /// </summary>
    public interface IApplicationRegistry2 : IApplicationRegistry {

        /// <summary>
        /// Physically remove the application from the database.
        /// Must be in deleted state.
        /// </summary>
        /// <param name="applicationId">The applicationId</param>
        /// <param name="force">Force the application to be deleted,
        /// even when not in deleted state</param>
        /// <returns></returns>
        Task DeleteApplicationAsync(string applicationId,
            bool force = false);

        /// <summary>
        /// Query for Applications sorted by ID.
        /// This query implements the search parameters required for the
        /// OPC UA GDS server QueryServers/QueryApplications API.
        /// </summary>
        /// <param name="request">Query</param>
        /// <returns></returns>
        Task<QueryApplicationsByIdResultModel> QueryApplicationsByIdAsync(
            QueryApplicationsByIdRequestModel request);
    }
}
