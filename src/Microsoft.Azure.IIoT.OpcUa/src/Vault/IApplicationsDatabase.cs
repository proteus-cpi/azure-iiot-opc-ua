// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace Microsoft.Azure.IIoT.OpcUa.Vault {
    using Microsoft.Azure.IIoT.OpcUa.Registry.Models;
    using System.Collections.Generic;
    using System.Threading.Tasks;

    /// <summary>
    /// Application Database interface.
    /// </summary>
    public interface IApplicationsDatabase {

        /// <TODO/>
        Task InitializeAsync();

        /// <summary>
        /// Register a new application.
        /// If the applicationId is not empty an Update is performed.
        /// </summary>
        /// <param name="application">The application record</param>
        Task<ApplicationInfoModel> RegisterApplicationAsync(
            ApplicationInfoModel application);

        /// <summary>
        /// Get the application by applicationId
        /// </summary>
        /// <param name="id">The applicationId</param>
        /// <returns>The application</returns>
        Task<ApplicationInfoModel> GetApplicationAsync(string id);

        /// <summary>
        /// Update an application.
        /// </summary>
        /// <param name="id">The applicationId</param>
        /// <param name="application">The application</param>
        /// <returns>The updated application</returns>
        Task<ApplicationInfoModel> UpdateApplicationAsync(string id,
            ApplicationInfoModel application);

        /// <summary>
        /// Approve or reject a new application.
        /// Application is in approved or rejected state after this call.
        /// </summary>
        /// <param name="id">The applicationId</param>
        /// <param name="approved">true if approved, false if rejected</param>
        /// <param name="force">Ignore state check</param>
        Task<ApplicationInfoModel> ApproveApplicationAsync(string id,
            bool approved, bool force);

        /// <summary>
        /// Unregister an application.
        /// After unregistering, the application is in deleted state but is
        /// not yet physically deleted, to maintain the history.
        /// All approved or accepted certificate requests of the application
        /// are also set to deleted state.
        /// The function is called Unregister instead of Delete to
        /// avoid confusion with
        /// a similar OPC UA GDS server function.
        /// </summary>
        /// <param name="id">The application Id</param>
        Task<ApplicationInfoModel> UnregisterApplicationAsync(string id);

        /// <summary>
        /// Physically remove the application form the database.
        /// Must be in deleted state.
        /// </summary>
        /// <param name="id">The applicationId</param>
        /// <param name="force">Force the application to be deleted,
        /// even when not in deleted state</param>
        /// <returns></returns>
        Task DeleteApplicationAsync(string id, bool force);

        /// <summary>
        /// List all applications with a ApplicationUri.
        /// </summary>
        /// <param name="uri">The ApplicationUri</param>
        /// <param name="nextPageLink"></param>
        /// <param name="pageSize"></param>
        /// <returns>The applications</returns>
        Task<IList<ApplicationInfoModel>> ListApplicationAsync(string uri,
            string nextPageLink = null, int? pageSize = null);

        /// <summary>
        /// Query for Applications sorted by ID.
        /// This query implements the search parameters required for the
        /// OPC UA GDS server QueryServers/QueryApplications API.
        /// </summary>
        /// <param name="request">Query</param>
        /// <returns></returns>
        Task<QueryApplicationsByIdResultModel> QueryApplicationsByIdAsync(
            QueryApplicationsByIdRequestModel request);

        /// <summary>
        /// Pageable query for applications with various search parameters.
        /// </summary>
        /// <param name="request">Query</param>
        /// <param name="nextPageLink">Next page link string
        /// </param>
        /// <param name="pageSize">Max number of applications
        /// to return</param>
        /// <returns></returns>
        Task<QueryApplicationsResultModel> QueryApplicationsAsync(
            QueryApplicationsRequestModel request, string nextPageLink = null,
            int? pageSize = null);
    }
}
