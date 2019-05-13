// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace Microsoft.Azure.IIoT.OpcUa.Vault.Tests {
    using Microsoft.Azure.IIoT.Auth.Clients;
    using Microsoft.Azure.IIoT.Auth.Clients.Default;
    using Microsoft.Azure.IIoT.Auth.Runtime;
    using Microsoft.Azure.IIoT.OpcUa.Registry.Tests;
    using Microsoft.Azure.IIoT.OpcUa.Vault.KeyVault.Clients;
    using Microsoft.Azure.IIoT.OpcUa.Vault.Models;
    using Microsoft.Azure.IIoT.OpcUa.Vault.Runtime;
    using Microsoft.Azure.IIoT.OpcUa.Vault.Services;
    using Microsoft.Extensions.Configuration;
    using Serilog;
    using System;
    using System.IO;
    using System.Threading;
    using System.Threading.Tasks;
    using Xunit;

    public class CertificateStorageTestFixture : IDisposable {

        public ApplicationTestDataGenerator RandomGenerator { get; set; }
        public KeyVaultGroupRegistry Registry { get; set; }
        public KeyVaultGroupServices Services { get; set; }
        public bool KeyVaultInitOk { get; set; }
        public string GroupId { get; }


        public CertificateStorageTestFixture() {
            var builder = new ConfigurationBuilder()
                .SetBasePath(Directory.GetCurrentDirectory())
                .AddJsonFile("testsettings.json", false, true)
                .AddJsonFile("testsettings.Development.json", true, true)
                .AddFromDotEnvFile()
                .AddEnvironmentVariables();
            var configuration = builder.Build();
            _serviceConfig = new VaultConfig(configuration);
            _clientConfig = new ClientConfig(configuration);
            _logger = SerilogTestLogger.Create<CertificateStorageTestFixture>();
            if (!InvalidConfiguration()) {
                RandomGenerator = new ApplicationTestDataGenerator();
                var timeid = DateTime.UtcNow.ToFileTimeUtc() / 1000 % 10000;
                GroupId = "GroupTestIssuerCA" + timeid.ToString();
                _keyVaultServiceClient = new KeyVaultServiceClient(_serviceConfig,
                    new AppAuthenticationProvider(_clientConfig), _logger);
                Registry = new KeyVaultGroupRegistry(_keyVaultServiceClient, _logger);
                Services = new KeyVaultGroupServices(Registry, _keyVaultServiceClient, _serviceConfig, _logger);
                _keyVaultServiceClient.PurgeAsync("groups", GroupId, CancellationToken.None).Wait();
                Registry.CreateGroupAsync(GroupId, "CN=OPC Vault Cert Request Test CA, O=Microsoft, OU=Azure IoT",
                    CertificateType.RsaSha256ApplicationCertificateType).Wait();
            }
            KeyVaultInitOk = false;
        }

        public void SkipOnInvalidConfiguration() {
            Skip.If(InvalidConfiguration(), "Missing valid KeyVault configuration.");
        }

        private bool InvalidConfiguration() {
            return
                string.IsNullOrEmpty(_serviceConfig.KeyVaultBaseUrl) ||
                string.IsNullOrEmpty(_serviceConfig.KeyVaultResourceId) ||
                string.IsNullOrEmpty(_clientConfig.AppId) ||
                string.IsNullOrEmpty(_clientConfig.AppSecret);
        }

        public void Dispose() {
            PurgeAsync().Wait();
        }

        public Task PurgeAsync() =>
            _keyVaultServiceClient?.PurgeAsync("groups", GroupId, CancellationToken.None);

        private readonly KeyVaultServiceClient _keyVaultServiceClient;
        private readonly VaultConfig _serviceConfig;
        private readonly IClientConfig _clientConfig;
        private readonly ILogger _logger;
    }
}
