// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace Microsoft.Azure.IIoT.OpcUa.Vault.Services {
    using Microsoft.Azure.IIoT.OpcUa.Vault.CosmosDB;
    using Autofac;
    using Serilog;
    using System;
    using System.Threading.Tasks;

    /// <summary>
    /// Helper to initialize all objects
    /// </summary>
    public class WarmStartDatabase : IStartable {

        /// <summary>
        /// Create starter
        /// </summary>
        /// <param name="repository"></param>
        /// <param name="certificateRequest"></param>
        /// <param name="applicationDatabase"></param>
        /// <param name="logger"></param>
        public WarmStartDatabase(IDocumentDBRepository repository,
            ICertificateRequest certificateRequest,
            IApplicationsDatabase applicationDatabase, ILogger logger) {
            _repository = repository;
            _certificateRequest = certificateRequest;
            _applicationDatabase = applicationDatabase;
            _logger = logger;
        }

        /// <inheritdoc/>
        public void Start() {
            Task.Run(async () => {
                try {
                    await _repository.CreateRepositoryIfNotExistsAsync();
                    await _applicationDatabase.InitializeAsync();
                    await _certificateRequest.InitializeAsync();
                    _logger.Information("Database warm start successful.");
                }
                catch (Exception ex) {
                    _logger.Error("Failed to warm start databases.", ex);
                }
            });
        }

        private readonly IDocumentDBRepository _repository;
        private readonly ICertificateRequest _certificateRequest;
        private readonly IApplicationsDatabase _applicationDatabase;
        private readonly ILogger _logger;
    }
}
