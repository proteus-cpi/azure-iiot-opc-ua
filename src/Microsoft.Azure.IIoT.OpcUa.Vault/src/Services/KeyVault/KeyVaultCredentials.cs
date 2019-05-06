// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace Microsoft.Azure.IIoT.OpcUa.Vault.KeyVault {
    using Microsoft.IdentityModel.Clients.ActiveDirectory;
    using Microsoft.Rest;
    using System;
    using System.Net.Http;
    using System.Net.Http.Headers;
    using System.Threading;
    using System.Threading.Tasks;

    /// <summary>
    /// Credentials used to use the keyvault client
    /// </summary>
    public class KeyVaultCredentials : ServiceClientCredentials {

        /// <summary>
        /// Create credentials
        /// </summary>
        /// <param name="bearerToken"></param>
        /// <param name="authority"></param>
        /// <param name="resourceId"></param>
        /// <param name="clientId"></param>
        /// <param name="clientSecret"></param>
        public KeyVaultCredentials(string bearerToken, string authority, string resourceId,
            string clientId, string clientSecret) {
            _bearerToken = bearerToken;
            _authority = authority;
            _resourceId = resourceId;
            _clientId = clientId;
            _clientSecret = clientSecret;
        }

        /// <inheritdoc/>
        public override void InitializeServiceClient<T>(ServiceClient<T> client) {
            var authenticationContext =
                new AuthenticationContext(_authority);

            var credential = new ClientCredential(
                _clientId,
                _clientSecret);

            var user = new UserAssertion(_bearerToken);

            var result = authenticationContext.AcquireTokenAsync(
                _resourceId,
                credential,
                userAssertion: user).GetAwaiter().GetResult();

            if (result == null) {
                throw new InvalidOperationException("Failed to obtain the JWT token");
            }

            _authenticationToken = result.AccessToken;
        }

        /// <inheritdoc/>
        public override async Task ProcessHttpRequestAsync(HttpRequestMessage request,
            CancellationToken cancellationToken) {
            if (request == null) {
                throw new ArgumentNullException(nameof(request));
            }

            if (_authenticationToken == null) {
                throw new InvalidOperationException("Token Provider Cannot Be Null");
            }

            request.Headers.Authorization = new AuthenticationHeaderValue(
                "Bearer", _authenticationToken);
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue(
                "application/json"));

            //request.Version = new Version(apiVersion);
            await base.ProcessHttpRequestAsync(request, cancellationToken);
        }

        private string _authenticationToken;
        private readonly string _authority;
        private readonly string _bearerToken;
        private readonly string _resourceId;
        private readonly string _clientId;
        private readonly string _clientSecret;
    }
}
