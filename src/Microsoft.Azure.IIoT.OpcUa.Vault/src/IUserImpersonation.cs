// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace Microsoft.Azure.IIoT.OpcUa.Vault {
    using Microsoft.AspNetCore.Http;
    using System.Threading.Tasks;

    /// <summary>
    /// Configures the service to send on behalf of a user
    /// </summary>
    public interface IUserImpersonation<TService> {

        /// <summary>
        /// Returns a shallow copy of the service which uses
        /// a token on behalf of a user.
        /// </summary>
        /// <param name="request">The http request with the user
        /// token</param>
        Task<TService> ImpersonateAsync(HttpRequest request);
    }
}
