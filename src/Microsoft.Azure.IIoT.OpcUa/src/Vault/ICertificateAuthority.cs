// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace Microsoft.Azure.IIoT.OpcUa.Vault {
    using Microsoft.Azure.IIoT.OpcUa.Vault.Models;
    using System.Threading.Tasks;

    /// <summary>
    /// An abstract interface to the certificate request database
    /// </summary>
    public interface ICertificateAuthority {

        /// <TODO/>
        Task InitializeAsync();

        /// <summary>
        /// Create a new certificate request with CSR.
        /// The CSR is validated and added to the database as new
        /// request.
        /// </summary>
        /// <param name="request">The request</param>
        /// <param name="authorityId">The authority Id adding the
        /// request
        /// </param>
        /// <returns></returns>
        Task<string> StartSigningRequestAsync(CreateSigningRequestModel request,
            string authorityId);

        /// <summary>
        /// Create a new certificate request with a public/private
        /// key pair.
        /// </summary>
        /// <param name="request">The request</param>
        /// <param name="authorityId">The authority Id adding the
        /// request</param>
        /// <returns>The request Id</returns>
        Task<string> StartNewKeyPairRequestAsync(CreateNewKeyPairRequestModel request,
            string authorityId);

        /// <summary>
        /// Approve a certificate request.
        /// The request is in approved state after the call.
        /// </summary>
        /// <param name="requestId">The request Id</param>
        Task ApproveAsync(string requestId);

        /// <summary>
        /// Reject a certificate request.
        /// The request is in rejected state after the call.
        /// </summary>
        /// <param name="requestId">The request Id</param>
        Task RejectAsync(string requestId);

        /// <summary>
        /// Accept a certificate request.
        /// The private key of an accepted certificate request is deleted.
        /// </summary>
        /// <param name="requestId">The request Id</param>
        Task AcceptAsync(string requestId);

        /// <summary>
        /// Delete a certificate request.
        /// The request is marked deleted until revocation.
        /// </summary>
        /// <param name="requestId">The request Id</param>
        Task DeleteAsync(string requestId);

        /// <summary>
        /// The request is removed from the database.
        /// </summary>
        /// <param name="requestId">The request Id</param>
        Task PurgeAsync(string requestId);

        /// <summary>
        /// Revoke the certificate of a request.
        /// </summary>
        /// <param name="requestId">The request Id</param>
        Task RevokeAsync(string requestId);

        /// <summary>
        /// Revoke all deleted certificate requests in a group.
        /// </summary>
        /// <param name="groupId">The group Id</param>
        /// <param name="allVersions">false to revoke only the lates
        /// Issuer CA cert</param>
        Task RevokeGroupAsync(string groupId, bool? allVersions);

        /// <summary>
        /// Fetch the data of a certificate requests.
        /// Can be used to query the request state and to read an
        /// issued certificate with a private key.
        /// </summary>
        /// <param name="requestId">The request Id</param>
        /// <param name="applicationId">The application Id</param>
        /// <returns>The request</returns>
        Task<FetchCertificateRequestResultModel> FetchRequestAsync(
            string requestId, string applicationId);

        /// <summary>
        /// Read a certificate request.
        /// Returns only public information, e.g. signed certificate.
        /// </summary>
        /// <param name="requestId"></param>
        /// <returns>The request</returns>
        Task<CertificateRequestRecordModel> ReadAsync(string requestId);

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
        Task<CertificateRequestQueryResultModel> QueryPageAsync(
            string appId, CertificateRequestState? state,
            string nextPageLink, int? maxResults = null);
    }
}
