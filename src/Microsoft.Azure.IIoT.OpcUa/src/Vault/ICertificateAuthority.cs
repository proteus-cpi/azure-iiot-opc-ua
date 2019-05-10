// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace Microsoft.Azure.IIoT.OpcUa.Vault {
    using Microsoft.Azure.IIoT.OpcUa.Vault.Models;
    using System.Threading.Tasks;

    /// <summary>
    /// Represents the interface to a certificate authority
    /// </summary>
    public interface ICertificateAuthority : ICertificateManagement {

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
        Task<string> SubmitSigningRequestAsync(
            SigningRequestModel request, string authorityId);

        /// <summary>
        /// Create a new certificate request with a public/private
        /// key pair.
        /// </summary>
        /// <param name="request">The request</param>
        /// <param name="authorityId">The authority Id adding the
        /// request</param>
        /// <returns>The request Id</returns>
        Task<string> SubmitNewKeyPairRequestAsync(
            NewKeyPairRequestModel request, string authorityId);

        /// <summary>
        /// Fetch the data of a certificate requests.
        /// Can be used to query the request state and to read an
        /// issued certificate with a private key.
        /// </summary>
        /// <param name="requestId">The request Id</param>
        /// <param name="applicationId">The application Id</param>
        /// <returns>The request</returns>
        Task<FetchCertificateRequestResultModel> FetchResultAsync(
            string requestId, string applicationId);

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
    }
}
