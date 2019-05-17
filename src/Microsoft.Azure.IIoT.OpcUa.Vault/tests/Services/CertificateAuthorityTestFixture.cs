// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------


namespace Microsoft.Azure.IIoT.OpcUa.Vault.Tests {
    using Microsoft.Azure.IIoT.Auth.Clients;
    using Microsoft.Azure.IIoT.Auth.Clients.Default;
    using Microsoft.Azure.IIoT.Auth.Runtime;
    using Microsoft.Azure.IIoT.Crypto.Default;
    using Microsoft.Azure.IIoT.Crypto.KeyVault.Clients;
    using Microsoft.Azure.IIoT.Crypto.KeyVault.Runtime;
    using Microsoft.Azure.IIoT.OpcUa.Registry;
    using Microsoft.Azure.IIoT.OpcUa.Registry.Tests;
    using Microsoft.Azure.IIoT.OpcUa.Vault;
    using Microsoft.Azure.IIoT.OpcUa.Vault.Runtime;
    using Microsoft.Azure.IIoT.OpcUa.Vault.Services;
    using Microsoft.Azure.IIoT.Storage.CosmosDb.Services;
    using Microsoft.Azure.IIoT.Storage.Default;
    using Microsoft.Extensions.Configuration;
    using Serilog;
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Threading;
    using Xunit;

    public class CertificateAuthorityTestFixture : IDisposable {
        public IApplicationRegistry2 ApplicationsDatabase { get; set; }
        public IGroupRegistry Registry { get; set; }
        public IGroupServices Services { get; set; }
        public ICertificateAuthority CertificateAuthority { get; set; }
        public IRequestManagement RequestManagement { get; set; }
        public IList<ApplicationTestData> ApplicationTestSet { get; set; }
        public ApplicationTestDataGenerator RandomGenerator { get; set; }
        public bool RegistrationOk { get; set; }

        public CertificateAuthorityTestFixture() {
            RandomGenerator = new ApplicationTestDataGenerator(kRandomStart);
            var builder = new ConfigurationBuilder()
                .SetBasePath(Directory.GetCurrentDirectory())
                .AddJsonFile("testsettings.json", false, true)
                .AddJsonFile("testsettings.Development.json", true, true)
                .AddFromDotEnvFile()
                .AddEnvironmentVariables();
            var configuration = builder.Build();
            _serviceConfig = new VaultConfig(configuration);
            _clientConfig = new ClientConfig(configuration);
            _logger = SerilogTestLogger.Create<CertificateAuthorityTestFixture>();
            if (!InvalidConfiguration()) {
                ApplicationsDatabase = new ApplicationDatabase(null, _serviceConfig,
                    new ItemContainerFactory(new CosmosDbServiceClient(_serviceConfig, _logger)), _logger);

                var timeid = DateTime.UtcNow.ToFileTimeUtc() / 1000 % 10000;

                // Create group registry
                Registry = new GroupDatabase(new ItemContainerFactory(
                    new CosmosDbServiceClient(_serviceConfig, _logger)), _logger);
                _groupId = Registry.CreateGroupAsync(new Models.CertificateGroupCreateRequestModel {
                    Name = "CertReqConfig" + timeid.ToString(),
                    SubjectName = "CN=OPC Vault Cert Request Test CA, O=Microsoft, OU=Azure IoT",
                    CertificateType = Models.CertificateType.RsaSha256ApplicationCertificateType
                }).Result.Id;

                // Create client
                _vaultConfig = new KeyVaultConfig(configuration);
                _keyVaultServiceClient = new KeyVaultServiceClient(_vaultConfig,
                    new AppAuthenticationProvider(_clientConfig), _logger);

                // Create services
                _keyVaultCertificateGroup = new CertificateServices(Registry,
                    _keyVaultServiceClient,
                    _keyVaultServiceClient,
                    new KeyValueCrlStore(_keyVaultServiceClient, _logger),
                    new CertificateRevoker(_keyVaultServiceClient, _logger),
                    new ApplicationCertificateFactory(_keyVaultServiceClient, _logger),
                    _serviceConfig,
                    _logger);
                _keyVaultServiceClient.PurgeAsync("groups", _groupId, CancellationToken.None).Wait();
                Services = _keyVaultCertificateGroup;

                CertificateAuthority = new CertificateAuthority(ApplicationsDatabase, Services,
                    new ItemContainerFactory(new CosmosDbServiceClient(_serviceConfig, _logger)), _logger);
                RequestManagement = (IRequestManagement)CertificateAuthority;

                // create test set
                ApplicationTestSet = new List<ApplicationTestData>();
                for (var i = 0; i < kTestSetSize; i++) {
                    var randomApp = RandomGenerator.RandomApplicationTestData();
                    ApplicationTestSet.Add(randomApp);
                }
            }
            RegistrationOk = false;
        }

        public void Dispose() {
            _keyVaultServiceClient?.PurgeAsync("groups", _groupId, CancellationToken.None).Wait();
        }

        public void SkipOnInvalidConfiguration() {
            Skip.If(InvalidConfiguration(), "Missing valid CosmosDB or KeyVault configuration.");
        }

        private bool InvalidConfiguration() {
            return
                string.IsNullOrEmpty(_vaultConfig.KeyVaultBaseUrl) ||
                string.IsNullOrEmpty(_vaultConfig.KeyVaultResourceId) ||
                string.IsNullOrEmpty(_clientConfig.AppId) ||
                string.IsNullOrEmpty(_clientConfig.AppSecret) ||
                string.IsNullOrEmpty(_serviceConfig.ContainerName) ||
                string.IsNullOrEmpty(_serviceConfig.DatabaseName) ||
                string.IsNullOrEmpty(_serviceConfig.DbConnectionString)
                ;
        }

        private readonly IClientConfig _clientConfig;
        private readonly VaultConfig _serviceConfig;
        private readonly KeyVaultConfig _vaultConfig;
        private readonly KeyVaultServiceClient _keyVaultServiceClient;
        private readonly CertificateServices _keyVaultCertificateGroup;
        private readonly ILogger _logger;
        private const int kRandomStart = 1234;
        private const int kTestSetSize = 10;
        private readonly string _groupId;
    }
}
