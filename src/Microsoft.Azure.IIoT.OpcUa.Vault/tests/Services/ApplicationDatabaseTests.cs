// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace Microsoft.Azure.IIoT.OpcUa.Registry.Tests {
    using Microsoft.Azure.IIoT.Exceptions;
    using Microsoft.Azure.IIoT.OpcUa.Registry.Models;
    using Microsoft.Azure.IIoT.OpcUa.Registry;
    using Microsoft.Azure.IIoT.OpcUa.Vault.Tests.Helpers;
    using Serilog;
    using System;
    using System.Collections.Generic;
    using System.Threading.Tasks;
    using TestCaseOrdering;
    using Xunit;
    using Xunit.Abstractions;

    [TestCaseOrderer("TestCaseOrdering.PriorityOrderer", "Microsoft.Azure.IIoT.OpcUa.Vault.Tests")]
    public class ApplicationDatabaseTests : IClassFixture<ApplicationDatabaseTestFixture> {

        public ApplicationDatabaseTests(ApplicationDatabaseTestFixture fixture, ITestOutputHelper log) {
            _fixture = fixture;
            // fixture
            _fixture.SkipOnInvalidConfiguration();
            _logger = SerilogTestLogger.Create<ApplicationDatabaseTests>(log);
            _applicationsDatabase = fixture.ApplicationsDatabase;
            _applicationTestSet = fixture.ApplicationTestSet;
        }

        /// <summary>
        /// Test to register all applications in the test set.
        /// </summary>
        [SkippableFact, Trait(Constants.Type, Constants.UnitTest), TestPriority(200)]
        public async Task RegisterAllApplications() {
            foreach (var application in _applicationTestSet) {
                Assert.Null(application.Model.Created);
                Assert.Null(application.Model.Approved);
                Assert.Null(application.Model.Updated);
                Assert.Null(application.Model.Deleted);
                var result = await _applicationsDatabase.RegisterApplicationAsync(
                    application.Model.ToRegistrationRequest());
                application.Model.ApplicationId = result.Id;
                var applicationModel = await _applicationsDatabase.GetApplicationAsync(application.Model.ApplicationId);
                Assert.NotNull(applicationModel);
                Assert.NotNull(applicationModel.Application.ApplicationId);
                Assert.Equal(result.Id, applicationModel.Application.ApplicationId);
                ApplicationTestData.AssertEqualApplicationModelData(applicationModel.Application, application.Model);
                application.Model = applicationModel.Application;
                Assert.NotNull(applicationModel);
            }
            _fixture.RegistrationOk = true;
        }

        /// <summary>
        /// Test to clean the database from collisions with the test set.
        /// </summary>
        [SkippableFact, Trait(Constants.Type, Constants.UnitTest), TestPriority(100)]
        public async Task CleanupAllApplications() {
            _logger.Information("Cleanup All Applications");
            foreach (var application in _applicationTestSet) {
                var applicationModelList = await _applicationsDatabase.ListApplicationsAsync(application.Model.ApplicationUri);
                Assert.NotNull(applicationModelList);
                foreach (var response in applicationModelList.Items) {
                    try {
                        await _applicationsDatabase.DeleteApplicationAsync(response.ApplicationId, true);
                    }
#pragma warning disable RECS0022 // A catch clause that catches System.Exception and has an empty body
                    catch { }
#pragma warning restore RECS0022 // A catch clause that catches System.Exception and has an empty body
                }
            }
            _fixture.RegistrationOk = false;
        }

        /// <summary>
        /// Test to register all applications in the test set.
        /// </summary>
        [SkippableFact, Trait(Constants.Type, Constants.UnitTest), TestPriority(200)]
        public async Task RegisterAllApplicationsThrow() {
            await Assert.ThrowsAsync<ArgumentNullException>(() => _applicationsDatabase.RegisterApplicationAsync(null));
        }

        /// <summary>
        /// Test the approve reject state machine.
        /// </summary>
        /// <remarks>After this test all applications are in the approved state.</remarks>
        [SkippableFact, Trait(Constants.Type, Constants.UnitTest), TestPriority(500)]
        public async Task ApproveAllApplications() {
            await Assert.ThrowsAsync<ArgumentNullException>(() => _applicationsDatabase.RejectApplicationAsync(null, false));
            await Assert.ThrowsAsync<ArgumentNullException>(() => _applicationsDatabase.RejectApplicationAsync("", false));

            Skip.If(!_fixture.RegistrationOk);
            var fullPasses = 0;
            foreach (var application in _applicationTestSet) {
                // read model to get state
                var applicationModel = await _applicationsDatabase.GetApplicationAsync(application.Model.ApplicationId);
                if (applicationModel.Application.State == ApplicationState.New) {
                    // approve app
                    await _applicationsDatabase.ApproveApplicationAsync(application.Model.ApplicationId, false);
                    applicationModel = await _applicationsDatabase.GetApplicationAsync(application.Model.ApplicationId);
                    Assert.NotNull(applicationModel);
                    Assert.Equal(ApplicationState.Approved, applicationModel.Application.State);
                }

                // verify start condition
                if (applicationModel.Application.State != ApplicationState.Approved) {
                    continue;
                }

                // reject approved app should fail
                await Assert.ThrowsAsync<ResourceInvalidStateException>(() => _applicationsDatabase.RejectApplicationAsync(application.Model.ApplicationId, false));

                // force approved app to rejected state
                await _applicationsDatabase.RejectApplicationAsync(application.Model.ApplicationId, true);
                applicationModel = await _applicationsDatabase.GetApplicationAsync(application.Model.ApplicationId);
                Assert.NotNull(applicationModel);
                Assert.NotNull(applicationModel.Application.ApplicationId);
                Assert.Equal(ApplicationState.Rejected, applicationModel.Application.State);
                ApplicationTestData.AssertEqualApplicationModelData(applicationModel.Application, application.Model);

                // approve rejected app should fail
                await Assert.ThrowsAsync<ResourceInvalidStateException>(() => _applicationsDatabase.ApproveApplicationAsync(application.Model.ApplicationId, false));

                // force approve of rejected app
                await _applicationsDatabase.ApproveApplicationAsync(application.Model.ApplicationId, true);
                applicationModel = await _applicationsDatabase.GetApplicationAsync(application.Model.ApplicationId);
                Assert.NotNull(applicationModel);
                Assert.NotNull(applicationModel.Application.ApplicationId);
                Assert.Equal(ApplicationState.Approved, applicationModel.Application.State);
                ApplicationTestData.AssertEqualApplicationModelData(applicationModel.Application, application.Model);
                fullPasses++;
            }
            // not enough test passes to verify
            Skip.If(fullPasses < _applicationTestSet.Count / 2);
        }

        [SkippableFact, Trait(Constants.Type, Constants.UnitTest), TestPriority(1000)]
        public async Task GetAllApplications() {
            await Assert.ThrowsAsync<ArgumentNullException>(() => _applicationsDatabase.GetApplicationAsync(null));
            await Assert.ThrowsAsync<ArgumentNullException>(() => _applicationsDatabase.GetApplicationAsync(""));
            await Assert.ThrowsAsync<ResourceNotFoundException>(() => _applicationsDatabase.GetApplicationAsync("abc"));
            await Assert.ThrowsAsync<ResourceNotFoundException>(() => _applicationsDatabase.GetApplicationAsync(Guid.NewGuid().ToString()));
            Skip.If(!_fixture.RegistrationOk);
            foreach (var application in _applicationTestSet) {
                var applicationModel = await _applicationsDatabase.GetApplicationAsync(application.Model.ApplicationId);
                Assert.NotNull(applicationModel);
                Assert.NotNull(applicationModel.Application.ApplicationId);
                ApplicationTestData.AssertEqualApplicationModelData(applicationModel.Application, application.Model);
            }
        }

        [SkippableFact, Trait(Constants.Type, Constants.UnitTest), TestPriority(1500)]
        public async Task ListAllApplications() {
            Skip.If(!_fixture.RegistrationOk);
            foreach (var application in _applicationTestSet) {
                var applicationModelList = await _applicationsDatabase.ListApplicationsAsync();
                Assert.NotNull(applicationModelList);
                Assert.True(applicationModelList.Items.Count >= 1, "At least one record should be found.");
                foreach (var response in applicationModelList.Items) {
                    Assert.NotNull(response.ApplicationId);
                }
            }
        }

        [SkippableFact, Trait(Constants.Type, Constants.UnitTest), TestPriority(1500)]
        public async Task QueryAllApplications() {
            Skip.If(!_fixture.RegistrationOk);
            foreach (var application in _applicationTestSet) {
                var applicationModelList = await _applicationsDatabase.QueryApplicationsAsync(
                    new ApplicationRegistrationQueryModel {
                        ApplicationUri = application.Model.ApplicationUri
                    });
                Assert.NotNull(applicationModelList);
                Assert.True(applicationModelList.Items.Count >= 1, "At least one record should be found.");
                foreach (var response in applicationModelList.Items) {
                    Assert.NotNull(response.ApplicationId);
                    Assert.Equal(application.Model.ApplicationUri, response.ApplicationUri);
                }
            }
        }

        [SkippableFact, Trait(Constants.Type, Constants.UnitTest), TestPriority(2100)]
        public async Task UpdateAllApplications() {
            Skip.If(!_fixture.RegistrationOk);
            foreach (var application in _applicationTestSet) {
                await _applicationsDatabase.UpdateApplicationAsync(application.Model.ApplicationId, application.Model.ToUpdateRequest());
                var applicationModel = await _applicationsDatabase.GetApplicationAsync(application.Model.ApplicationId);
                Assert.NotNull(applicationModel);
                Assert.NotNull(applicationModel.Application.ApplicationId);
            }
        }

        [SkippableFact, Trait(Constants.Type, Constants.UnitTest), TestPriority(2200)]
        public async Task QueryApplicationsByIdAsync() {
            Skip.If(!_fixture.RegistrationOk);
            foreach (var application in _applicationTestSet) {
                var response = await _applicationsDatabase.QueryApplicationsByIdAsync(
                    new QueryApplicationsByIdRequestModel {
                        ApplicationState = ApplicationStateMask.Any
                    });
                Assert.NotNull(response);
            }
        }

        [SkippableFact, Trait(Constants.Type, Constants.UnitTest), TestPriority(2300)]
        public async Task QueryApplicationsAsync() {
            Skip.If(!_fixture.RegistrationOk);
            foreach (var application in _applicationTestSet) {
                var response = await _applicationsDatabase.QueryApplicationsAsync(
                    new ApplicationRegistrationQueryModel {
                        State = ApplicationStateMask.Any
                    });
                Assert.NotNull(response);
            }
        }

        [SkippableFact, Trait(Constants.Type, Constants.UnitTest), TestPriority(8000)]
        public async Task UnregisterAllApplications() {
            Skip.If(!_fixture.RegistrationOk);
            foreach (var application in _applicationTestSet) {
                await _applicationsDatabase.UnregisterApplicationAsync(
                    application.Model.ApplicationId);
            }
        }

        [SkippableFact, Trait(Constants.Type, Constants.UnitTest), TestPriority(8100)]
        public async Task UnregisteredListAllApplications() {
            Skip.If(!_fixture.RegistrationOk);
            foreach (var application in _applicationTestSet) {
                var applicationModelList = await _applicationsDatabase.QueryApplicationsAsync(
                    new ApplicationRegistrationQueryModel {
                        ApplicationUri = application.Model.ApplicationUri,
                        State = ApplicationStateMask.Unregistered
                    });
                Assert.NotNull(applicationModelList);
                foreach (var response in applicationModelList.Items) {
                    Assert.Equal(application.Model.ApplicationUri, response.ApplicationUri);
                    Assert.Equal(ApplicationState.Unregistered, response.State);
                }
            }
        }

        [SkippableFact, Trait(Constants.Type, Constants.UnitTest), TestPriority(8200)]
        public async Task UnregisteredGetAllApplicationsNot() {
            Skip.If(!_fixture.RegistrationOk);
            foreach (var application in _applicationTestSet) {
                var applicationModel = await _applicationsDatabase.GetApplicationAsync(
                    application.Model.ApplicationId);
                Assert.NotNull(applicationModel);
                Assert.NotNull(applicationModel.Application.ApplicationId);
                Assert.Equal(ApplicationState.Unregistered, applicationModel.Application.State);
                Assert.NotNull(applicationModel.Application.Deleted);
                ApplicationTestData.AssertEqualApplicationModelData(applicationModel.Application, application.Model);
            }
        }

        [SkippableFact, Trait(Constants.Type, Constants.UnitTest), TestPriority(9000)]
        public async Task DeleteAllApplications() {
            Skip.If(!_fixture.RegistrationOk);
            foreach (var application in _applicationTestSet) {
                await _applicationsDatabase.DeleteApplicationAsync(
                    application.Model.ApplicationId, false);
            }
        }

        [SkippableFact, Trait(Constants.Type, Constants.UnitTest), TestPriority(9200)]
        public async Task DeletedGetAllApplications() {
            Skip.If(!_fixture.RegistrationOk);
            foreach (var application in _applicationTestSet) {
                await Assert.ThrowsAsync<ResourceNotFoundException>(async () => {
                    var applicationModel = await _applicationsDatabase.GetApplicationAsync(
                        application.Model.ApplicationId);
                });
            }
        }
        private readonly ApplicationDatabaseTestFixture _fixture;
        private readonly ILogger _logger;
        private readonly IApplicationRegistry2 _applicationsDatabase;
        private readonly IList<ApplicationTestData> _applicationTestSet;
    }
}
