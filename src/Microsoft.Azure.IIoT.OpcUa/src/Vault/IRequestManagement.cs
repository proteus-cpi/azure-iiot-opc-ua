// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace Microsoft.Azure.IIoT.OpcUa.Vault {
    using Microsoft.Azure.IIoT.OpcUa.Vault.Models;
    using System.Threading.Tasks;

    /// <summary>
    /// Represents the certificate management workflow
    /// </summary>
    public interface IRequestManagement {

        /// <summary>
        /// Approve a certificate request.
        /// The request is in approved state after the call.
        /// </summary>
        /// <param name="requestId">The request Id</param>
        Task ApproveRequestAsync(string requestId);

        /// <summary>
        /// Reject a certificate request.
        /// The request is in rejected state after the call.
        /// </summary>
        /// <param name="requestId">The request Id</param>
        Task RejectRequestAsync(string requestId);

        /// <summary>
        /// Accept a certificate request.
        /// The private key of an accepted certificate request is deleted.
        /// </summary>
        /// <param name="requestId">The request Id</param>
        Task AcceptRequestAsync(string requestId);

        /// <summary>
        /// Read a certificate request.
        /// Returns only public information, e.g. signed certificate.
        /// </summary>
        /// <param name="requestId"></param>
        /// <returns>The request</returns>
        Task<CertificateRequestRecordModel> GetRequestAsync(
            string requestId);

        /// <summary>
        /// Query the certificate request database.
        /// </summary>
        /// <param name="appId">Filter by ApplicationId</param>
        /// <param name="state">Filter by state, default null</param>
        /// <param name="nextPageLink">The next page</param>
        /// <param name="maxResults">max number of requests in a query
        /// </param>
        /// <returns>Array of certificate requests, next page link
        /// </returns>
        Task<CertificateRequestQueryResultModel> QueryRequestsAsync(
            string appId, CertificateRequestState? state,
            string nextPageLink, int? maxResults = null);

        /// <summary>
        /// Delete a certificate request.
        /// The request is marked deleted until revocation.
        /// </summary>
        /// <param name="requestId">The request Id</param>
        Task DeleteRequestAsync(string requestId);

        /// <summary>
        /// The request is removed from the database.
        /// </summary>
        /// <param name="requestId">The request Id</param>
        Task PurgeRequestAsync(string requestId);

        /// <summary>
        /// Revoke the certificate of a request.
        /// </summary>
        /// <param name="requestId">The request Id</param>
        Task RevokeRequestCertificateAsync(string requestId);

        /// <summary>
        /// Revoke all deleted certificate requests in a group.
        /// </summary>
        /// <param name="groupId">The group Id</param>
        /// <param name="allVersions">false to revoke only the lates
        /// Issuer CA cert</param>
        Task RevokeAllRequestsAsync(string groupId,
            bool? allVersions);
    }
}
