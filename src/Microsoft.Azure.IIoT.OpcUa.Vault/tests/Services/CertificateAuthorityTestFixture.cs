﻿// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------


namespace Microsoft.Azure.IIoT.OpcUa.Vault.Tests {
    using Microsoft.Azure.IIoT.Auth.Clients;
    using Microsoft.Azure.IIoT.Auth.Runtime;
    using Microsoft.Azure.IIoT.OpcUa.Vault;
    using Microsoft.Azure.IIoT.OpcUa.Vault.Services.CosmosDB;
    using Microsoft.Azure.IIoT.OpcUa.Vault.Services.CosmosDB.Services;
    using Microsoft.Azure.IIoT.OpcUa.Vault.Services;
    using Microsoft.Azure.IIoT.OpcUa.Vault.Runtime;
    using Microsoft.Extensions.Configuration;
    using Serilog;
    using System;
    using System.Collections.Generic;
    using System.IO;
    using Xunit;
    using Microsoft.Azure.IIoT.OpcUa.Registry;
    using Microsoft.Azure.IIoT.OpcUa.Registry.Tests;
    using Microsoft.Azure.IIoT.Storage.Default;
    using Microsoft.Azure.IIoT.Storage.CosmosDb.Services;

    public class CertificateAuthorityTestFixture : IDisposable {
        public IApplicationRegistry2 ApplicationsDatabase { get; set; }
        public ICertificateStorage CertificateGroup { get; set; }
        public ICertificateAuthority CertificateRequest { get; set; }
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
                _documentDBRepository = new DocumentDBRepository(_serviceConfig);
                ApplicationsDatabase = new ApplicationDatabase(null, _serviceConfig, 
                    new ItemContainerFactory(new CosmosDbServiceClient(_serviceConfig, _logger)), _logger);

                var timeid = DateTime.UtcNow.ToFileTimeUtc() / 1000 % 10000;
                _groupId = "CertReqIssuerCA" + timeid.ToString();
                _configId = "CertReqConfig" + timeid.ToString();
                var keyVaultServiceClient = KeyVaultTestServiceClient.Get(_configId, _serviceConfig, _clientConfig, _logger);
                _keyVaultCertificateGroup = new CertificateManagement(keyVaultServiceClient, _serviceConfig, _logger);
                _keyVaultCertificateGroup.PurgeAsync(_configId, _groupId).Wait();
                CertificateGroup = new CertificateManagement(keyVaultServiceClient, _serviceConfig, _logger);
                CertificateGroup.CreateGroupAsync(_groupId,
                    "CN=OPC Vault Cert Request Test CA, O=Microsoft, OU=Azure IoT", Models.CertificateType.RsaSha256ApplicationCertificateType).Wait();
                CertificateRequest = new CertificateAuthority(ApplicationsDatabase, CertificateGroup, _serviceConfig,
                    _documentDBRepository, _logger);

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
            _keyVaultCertificateGroup?.PurgeAsync(_configId, _groupId).Wait();
        }

        public void SkipOnInvalidConfiguration() {
            Skip.If(InvalidConfiguration(), "Missing valid CosmosDB or KeyVault configuration.");
        }

        private bool InvalidConfiguration() {
            return
                string.IsNullOrEmpty(_serviceConfig.KeyVaultBaseUrl) ||
                string.IsNullOrEmpty(_serviceConfig.KeyVaultResourceId) ||
                string.IsNullOrEmpty(_clientConfig.AppId) ||
                string.IsNullOrEmpty(_clientConfig.AppSecret) ||
                string.IsNullOrEmpty(_serviceConfig.ContainerName) ||
                string.IsNullOrEmpty(_serviceConfig.DatabaseName) ||
                string.IsNullOrEmpty(_serviceConfig.DbConnectionString)
                ;
        }

        private readonly IClientConfig _clientConfig;
        private readonly IDocumentDBRepository _documentDBRepository;
        private readonly VaultConfig _serviceConfig;
        private readonly string _configId;
        private readonly string _groupId;
        private readonly CertificateManagement _keyVaultCertificateGroup;
        private readonly ILogger _logger;
        private const int kRandomStart = 1234;
        private const int kTestSetSize = 10;
    }
}
