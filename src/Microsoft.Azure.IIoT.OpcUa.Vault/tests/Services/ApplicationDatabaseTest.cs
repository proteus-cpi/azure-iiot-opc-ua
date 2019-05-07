// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------


using Microsoft.Azure.IIoT.Exceptions;
using Microsoft.Azure.IIoT.OpcUa.Vault;
using Microsoft.Azure.IIoT.OpcUa.Vault.Models;
using Microsoft.Azure.IIoT.OpcUa.Vault.Tests.Helpers;
using Serilog;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using TestCaseOrdering;
using Xunit;
using Xunit.Abstractions;

namespace Microsoft.Azure.IIoT.OpcUa.Vault.Tests {

    [TestCaseOrderer("TestCaseOrdering.PriorityOrderer", "Microsoft.Azure.IIoT.OpcUa.Vault.Tests")]
    public class ApplicationDatabaseTest : IClassFixture<ApplicationDatabaseTestFixture> {

        public ApplicationDatabaseTest(ApplicationDatabaseTestFixture fixture, ITestOutputHelper log) {
            _fixture = fixture;
            // fixture
            _fixture.SkipOnInvalidConfiguration();
            _logger = SerilogTestLogger.Create<ApplicationDatabaseTest>(log);
            _applicationsDatabase = fixture.ApplicationsDatabase;
            _applicationTestSet = fixture.ApplicationTestSet;
        }

        /// <summary>
        /// Test to register all applications in the test set.
        /// </summary>
        [SkippableFact, Trait(Constants.Type, Constants.UnitTest), TestPriority(200)]
        public async Task RegisterAllApplications() {
            foreach (var application in _applicationTestSet) {
                Assert.Null(application.Model.CreateTime);
                Assert.Null(application.Model.ApproveTime);
                Assert.Null(application.Model.UpdateTime);
                Assert.Null(application.Model.DeleteTime);
                var applicationModel = await _applicationsDatabase.RegisterApplicationAsync(application.Model);
                Assert.NotNull(applicationModel);
                Assert.NotNull(applicationModel.ApplicationId);
                ApplicationTestData.AssertEqualApplicationModelData(applicationModel, application.Model);
                application.Model = applicationModel;
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
                var applicationModelList = await _applicationsDatabase.ListApplicationAsync(application.Model.ApplicationUri);
                Assert.NotNull(applicationModelList);
                foreach (var response in applicationModelList) {
                    try {
                        await _applicationsDatabase.DeleteApplicationAsync(response.ApplicationId.ToString(), true);
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
            await Assert.ThrowsAsync<ResourceNotFoundException>(async () => {
                var testModelCopy = ApplicationTestData.ApplicationDeepCopy(_applicationTestSet[0].Model);
                testModelCopy.ApplicationId = Guid.NewGuid().ToString();
                await _applicationsDatabase.RegisterApplicationAsync(testModelCopy);
            });
        }

        /// <summary>
        /// Test the approve reject state machine.
        /// </summary>
        /// <remarks>After this test all applications are in the approved state.</remarks>
        [SkippableFact, Trait(Constants.Type, Constants.UnitTest), TestPriority(500)]
        public async Task ApproveAllApplications() {
            await Assert.ThrowsAsync<ArgumentNullException>(() => _applicationsDatabase.ApproveApplicationAsync(null, false, false));

            await Assert.ThrowsAsync<ArgumentException>(() => _applicationsDatabase.ApproveApplicationAsync(Guid.Empty.ToString(), false, false));

            Skip.If(!_fixture.RegistrationOk);
            var fullPasses = 0;
            foreach (var application in _applicationTestSet) {
                // read model to get state
                var applicationModel = await _applicationsDatabase.GetApplicationAsync(application.Model.ApplicationId.ToString());
                if (applicationModel.State == ApplicationState.New) {
                    // approve app
                    applicationModel = await _applicationsDatabase.ApproveApplicationAsync(application.Model.ApplicationId.ToString(), true, false);
                    Assert.NotNull(applicationModel);
                    Assert.Equal(ApplicationState.Approved, applicationModel.State);
                }

                // verify start condition
                if (applicationModel.State != ApplicationState.Approved) {
                    continue;
                }

                // reject approved app should fail
                await Assert.ThrowsAsync<ResourceInvalidStateException>(() => _applicationsDatabase.ApproveApplicationAsync(application.Model.ApplicationId.ToString(), false, false));

                // force approved app to rejected state
                applicationModel = await _applicationsDatabase.ApproveApplicationAsync(application.Model.ApplicationId.ToString(), false, true);
                Assert.NotNull(applicationModel);
                Assert.NotNull(applicationModel.ApplicationId);
                Assert.Equal(ApplicationState.Rejected, applicationModel.State);
                ApplicationTestData.AssertEqualApplicationModelData(applicationModel, application.Model);

                // approve rejected app should fail
                await Assert.ThrowsAsync<ResourceInvalidStateException>(() => _applicationsDatabase.ApproveApplicationAsync(application.Model.ApplicationId.ToString(), true, false));

                // force approve of rejected app
                applicationModel = await _applicationsDatabase.ApproveApplicationAsync(application.Model.ApplicationId.ToString(), true, true);
                Assert.NotNull(applicationModel);
                Assert.NotNull(applicationModel.ApplicationId);
                Assert.Equal(ApplicationState.Approved, applicationModel.State);
                ApplicationTestData.AssertEqualApplicationModelData(applicationModel, application.Model);
                fullPasses++;
            }
            // not enough test passes to verify
            Skip.If(fullPasses < _applicationTestSet.Count / 2);
        }

        [SkippableFact, Trait(Constants.Type, Constants.UnitTest), TestPriority(1000)]
        public async Task GetAllApplications() {
            await Assert.ThrowsAsync<ArgumentNullException>(() => _applicationsDatabase.GetApplicationAsync(null));
            await Assert.ThrowsAsync<ArgumentException>(() => _applicationsDatabase.GetApplicationAsync(Guid.Empty.ToString()));
            await Assert.ThrowsAsync<ArgumentException>(() => _applicationsDatabase.GetApplicationAsync("abc"));
            await Assert.ThrowsAsync<ResourceNotFoundException>(() => _applicationsDatabase.GetApplicationAsync(Guid.NewGuid().ToString()));
            Skip.If(!_fixture.RegistrationOk);
            foreach (var application in _applicationTestSet) {
                var applicationModel = await _applicationsDatabase.GetApplicationAsync(application.Model.ApplicationId.ToString());
                Assert.NotNull(applicationModel);
                Assert.NotNull(applicationModel.ApplicationId);
                Assert.Equal(applicationModel.ApplicationId, applicationModel.ApplicationId);
                ApplicationTestData.AssertEqualApplicationModelData(applicationModel, application.Model);
            }
        }

        [SkippableFact, Trait(Constants.Type, Constants.UnitTest), TestPriority(1500)]
        public async Task ListAllApplications() {
            Skip.If(!_fixture.RegistrationOk);
            foreach (var application in _applicationTestSet) {
                var applicationModelList = await _applicationsDatabase.ListApplicationAsync(
                    application.Model.ApplicationUri);
                Assert.NotNull(applicationModelList);
                Assert.True(applicationModelList.Count >= 1, "At least one record should be found.");
                foreach (var response in applicationModelList) {
                    Assert.NotNull(response.ApplicationId);
                    Assert.Equal(application.Model.ApplicationUri, response.ApplicationUri);
                }
            }
        }

        [SkippableFact, Trait(Constants.Type, Constants.UnitTest), TestPriority(2100)]
        public async Task UpdateAllApplications() {
            Skip.If(!_fixture.RegistrationOk);
            foreach (var application in _applicationTestSet) {
                var applicationModel = await _applicationsDatabase.UpdateApplicationAsync(
                    application.Model.ApplicationId.ToString(), application.Model);
                Assert.NotNull(applicationModel);
                Assert.NotNull(applicationModel.ApplicationId);
                Assert.Equal(applicationModel.ApplicationId, applicationModel.ApplicationId);
            }
        }

        [SkippableFact, Trait(Constants.Type, Constants.UnitTest), TestPriority(2200)]
        public async Task QueryApplicationsByIdAsync() {
            Skip.If(!_fixture.RegistrationOk);
            foreach (var application in _applicationTestSet) {
                var response = await _applicationsDatabase.QueryApplicationsByIdAsync(
                    0, 0, null, null, 0, null, null, QueryApplicationState.Any);
                Assert.NotNull(response);
            }
        }

        [SkippableFact, Trait(Constants.Type, Constants.UnitTest), TestPriority(2300)]
        public async Task QueryApplicationsAsync() {
            Skip.If(!_fixture.RegistrationOk);
            foreach (var application in _applicationTestSet) {
                var response = await _applicationsDatabase.QueryApplicationsAsync(
                    null, null, 0, null, null, QueryApplicationState.Any);
                Assert.NotNull(response);
            }
        }

        [SkippableFact, Trait(Constants.Type, Constants.UnitTest), TestPriority(8000)]
        public async Task UnregisterAllApplications() {
            Skip.If(!_fixture.RegistrationOk);
            foreach (var application in _applicationTestSet) {
                var applicationModel = await _applicationsDatabase.UnregisterApplicationAsync(
                    application.Model.ApplicationId.ToString());
                Assert.NotNull(applicationModel);
                Assert.NotNull(applicationModel.ApplicationId);
            }
        }

        [SkippableFact, Trait(Constants.Type, Constants.UnitTest), TestPriority(8100)]
        public async Task UnregisteredListAllApplications() {
            Skip.If(!_fixture.RegistrationOk);
            foreach (var application in _applicationTestSet) {
                var applicationModelList = await _applicationsDatabase.ListApplicationAsync(
                    application.Model.ApplicationUri);
                Assert.NotNull(applicationModelList);
                foreach (var response in applicationModelList) {
                    Assert.Equal(application.Model.ApplicationUri, response.ApplicationUri);
                    Assert.NotEqual(response.ApplicationId, application.Model.ApplicationId);
                }
            }
        }

        [SkippableFact, Trait(Constants.Type, Constants.UnitTest), TestPriority(8200)]
        public async Task UnregisteredGetAllApplicationsNot() {
            Skip.If(!_fixture.RegistrationOk);
            foreach (var application in _applicationTestSet) {
                var applicationModel = await _applicationsDatabase.GetApplicationAsync(
                    application.Model.ApplicationId.ToString());
                Assert.NotNull(applicationModel);
                Assert.NotNull(applicationModel.ApplicationId);
                Assert.Equal(applicationModel.ApplicationId, applicationModel.ApplicationId);
                Assert.Equal(ApplicationState.Unregistered, applicationModel.State);
                Assert.NotNull(applicationModel.DeleteTime);
                ApplicationTestData.AssertEqualApplicationModelData(applicationModel, application.Model);
            }
        }

        [SkippableFact, Trait(Constants.Type, Constants.UnitTest), TestPriority(9000)]
        public async Task DeleteAllApplications() {
            Skip.If(!_fixture.RegistrationOk);
            foreach (var application in _applicationTestSet) {
                await _applicationsDatabase.DeleteApplicationAsync(
                    application.Model.ApplicationId.ToString(), false);
            }
        }

        [SkippableFact, Trait(Constants.Type, Constants.UnitTest), TestPriority(9200)]
        public async Task DeletedGetAllApplications() {
            Skip.If(!_fixture.RegistrationOk);
            foreach (var application in _applicationTestSet) {
                await Assert.ThrowsAsync<ResourceNotFoundException>(async () => {
                    var applicationModel = await _applicationsDatabase.GetApplicationAsync(
                        application.Model.ApplicationId.ToString());
                });
            }
        }
        private readonly ApplicationDatabaseTestFixture _fixture;
        private readonly ILogger _logger;
        private readonly IApplicationsDatabase _applicationsDatabase;
        private readonly IList<ApplicationTestData> _applicationTestSet;
    }
}
