// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------


namespace Microsoft.Azure.IIoT.OpcUa.Registry.Tests {
    using Microsoft.Azure.IIoT.Auth.Clients;
    using Microsoft.Azure.IIoT.Auth.Runtime;
    using Microsoft.Azure.IIoT.OpcUa.Registry;
    using Microsoft.Azure.IIoT.OpcUa.Vault.Runtime;
    using Microsoft.Azure.IIoT.OpcUa.Vault.Services;
    using Microsoft.Azure.IIoT.Storage.CosmosDb.Services;
    using Microsoft.Azure.IIoT.Storage.Default;
    using Microsoft.Extensions.Configuration;
    using Serilog;
    using System;
    using System.Collections.Generic;
    using System.IO;
    using Xunit;

    public class ApplicationDatabaseTestFixture : IDisposable {

        public IApplicationRegistry2 ApplicationsDatabase { get; set; }
        public IList<ApplicationTestData> ApplicationTestSet { get; set; }
        public ApplicationTestDataGenerator RandomGenerator { get; set; }
        public bool RegistrationOk { get; set; }

        public ApplicationDatabaseTestFixture() {
            var builder = new ConfigurationBuilder()
                .SetBasePath(Directory.GetCurrentDirectory())
                .AddJsonFile("testsettings.json", false, true)
                .AddJsonFile("testsettings.Development.json", true, true)
                .AddFromDotEnvFile()
                .AddEnvironmentVariables();
            _configuration = builder.Build();
            _serviceConfig = new VaultConfig(_configuration);
            _logger = SerilogTestLogger.Create<ApplicationDatabaseTestFixture>();
            if (!InvalidConfiguration()) {
                RandomGenerator = new ApplicationTestDataGenerator(kRandomStart);
                ApplicationsDatabase = new ApplicationDatabase(null, _serviceConfig,
                    new ItemContainerFactory(new CosmosDbServiceClient(_serviceConfig, _logger)), _logger);
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
        }

        public void SkipOnInvalidConfiguration() {
            Skip.If(InvalidConfiguration(), "Missing valid CosmosDB configuration.");
        }

        private bool InvalidConfiguration() {
            return
            string.IsNullOrEmpty(_serviceConfig.ContainerName) ||
            string.IsNullOrEmpty(_serviceConfig.DatabaseName) ||
            string.IsNullOrEmpty(_serviceConfig.DbConnectionString)
            ;
        }

        private readonly ILogger _logger;
        private readonly VaultConfig _serviceConfig;
        private readonly IConfigurationRoot _configuration;
        private const int kRandomStart = 3388;
        private const int kTestSetSize = 10;
    }
}
