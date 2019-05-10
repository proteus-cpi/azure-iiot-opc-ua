// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace Microsoft.Azure.IIoT.OpcUa.Vault {
    using System.Threading.Tasks;

    /// <summary>
    /// Represents the management interface
    /// </summary>
    public interface ICertificateManagement {

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
