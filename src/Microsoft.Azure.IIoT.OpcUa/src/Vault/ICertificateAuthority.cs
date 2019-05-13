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
    public interface ICertificateAuthority {

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
    }
}
