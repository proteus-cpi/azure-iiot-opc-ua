// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace Microsoft.Azure.IIoT.OpcUa.Vault.Tests {
    using Microsoft.Azure.IIoT.Auth.Clients;
    using Microsoft.Azure.IIoT.Auth.Runtime;
    using Microsoft.Azure.IIoT.OpcUa.Vault.Services;
    using Microsoft.Azure.IIoT.OpcUa.Vault.Runtime;
    using Microsoft.Extensions.Configuration;
    using Serilog;
    using System;
    using System.IO;
    using Xunit;

    public class CertificateGroupTestFixture : IDisposable {
        public ApplicationTestDataGenerator RandomGenerator { get; set; }
        public KeyVaultCertificateGroup KeyVault { get; set; }
        public bool KeyVaultInitOk { get; set; }
        public string ConfigId { get;  }
        public string GroupId { get;  }

        public CertificateGroupTestFixture() {
            var builder = new ConfigurationBuilder()
                .SetBasePath(Directory.GetCurrentDirectory())
                .AddJsonFile("testsettings.json", false, true)
                .AddJsonFile("testsettings.Development.json", true, true)
                .AddFromDotEnvFile()
                .AddEnvironmentVariables();
            var configuration = builder.Build();
            _serviceConfig = new ServiceConfig(configuration);
            _clientConfig = new ClientConfig(configuration);
            _logger = SerilogTestLogger.Create<CertificateGroupTestFixture>();
            if (!InvalidConfiguration()) {
                RandomGenerator = new ApplicationTestDataGenerator();
                var timeid = DateTime.UtcNow.ToFileTimeUtc() / 1000 % 10000;
                GroupId = "GroupTestIssuerCA" + timeid.ToString();
                ConfigId = "GroupTestConfig" + timeid.ToString();
                var keyVaultServiceClient = KeyVaultTestServiceClient.Get(ConfigId, _serviceConfig, _clientConfig, _logger);
                KeyVault = new KeyVaultCertificateGroup(keyVaultServiceClient, _serviceConfig, _clientConfig, _logger);
                KeyVault.PurgeAsync(ConfigId, GroupId).Wait();
                KeyVault.CreateCertificateGroupConfigurationAsync(GroupId, "CN=OPC Vault Cert Request Test CA, O=Microsoft, OU=Azure IoT", null).Wait();
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
            KeyVault?.PurgeAsync(ConfigId, GroupId).Wait();
        }

        private readonly ServiceConfig _serviceConfig;
        private readonly IClientConfig _clientConfig;
        private readonly ILogger _logger;
    }
}
