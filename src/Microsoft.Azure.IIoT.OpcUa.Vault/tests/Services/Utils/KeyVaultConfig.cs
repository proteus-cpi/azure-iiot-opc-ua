// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace Microsoft.Azure.IIoT.OpcUa.Vault.Tests {
    using Microsoft.Azure.IIoT.Auth.Clients;
    using Microsoft.Azure.IIoT.Auth.Clients.Default;
    using Microsoft.Azure.IIoT.OpcUa.Vault.KeyVault;
    using Microsoft.Azure.IIoT.OpcUa.Vault.KeyVault.Clients;
    using Serilog;
    public static class KeyVaultTestServiceClient {

        public static IKeyVault Get(IVaultConfig _serviceConfig,
            IClientConfig _clientConfig, ILogger logger) {
            var _keyVaultServiceClient = new KeyVaultServiceClient(_serviceConfig,
                new AppAuthenticationProvider(_clientConfig), logger);
            return _keyVaultServiceClient;
        }
    }
}
