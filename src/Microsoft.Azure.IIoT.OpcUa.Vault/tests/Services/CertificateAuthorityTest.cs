// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------


namespace Microsoft.Azure.IIoT.OpcUa.Vault.Tests {
    using Microsoft.Azure.IIoT.Exceptions;
    using Microsoft.Azure.IIoT.OpcUa.Registry.Models;
    using Microsoft.Azure.IIoT.OpcUa.Vault;
    using Microsoft.Azure.IIoT.OpcUa.Vault.Models;
    using Microsoft.Azure.IIoT.OpcUa.Vault.Tests.Helpers;
    using Opc.Ua.Test;
    using Serilog;
    using System;
    using System.Collections.Generic;
    using System.Threading.Tasks;
    using TestCaseOrdering;
    using Xunit;
    using Xunit.Abstractions;

    [TestCaseOrderer("TestCaseOrdering.PriorityOrderer", "Microsoft.Azure.IIoT.OpcUa.Vault.Tests")]
    public class CertificateAuthorityTest : IClassFixture<CertificateAuthorityTestFixture> {

        public CertificateAuthorityTest(CertificateAuthorityTestFixture fixture, ITestOutputHelper log) {
            _fixture = fixture;
            // fixture
            fixture.SkipOnInvalidConfiguration();
            _logger = SerilogTestLogger.Create<CertificateAuthorityTest>(log);
            _applicationsDatabase = fixture.ApplicationsDatabase;
            _certificateGroup = fixture.CertificateGroup;
            _certificateRequest = fixture.CertificateRequest;
            _applicationTestSet = fixture.ApplicationTestSet;
            _randomSource = new RandomSource(10815);
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
        public async Task RegisterAllApplications() {
            foreach (var application in _applicationTestSet) {
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
        /// Initialize certificate request class.
        /// </summary>
        [SkippableFact, Trait(Constants.Type, Constants.UnitTest), TestPriority(190)]
        public async Task InitCertificateRequestAndGroup() {
            await _certificateRequest.InitializeAsync();
            var groups = await _certificateGroup.GetGroupIdsAsync();
            foreach (var group in groups) {
                await _certificateGroup.CreateIssuerCACertificateAsync(group);
                var chain = await _certificateGroup.GetIssuerCACertificateChainAsync(group);
                Assert.NotNull(chain);
                Assert.True(chain.Chain.Count > 0);
            }
        }

        /// <summary>
        /// Approve all applications, the valid state for cert requests.
        /// </summary>
        /// <remarks>After this test all applications are in the approved state.</remarks>
        [SkippableFact, Trait(Constants.Type, Constants.UnitTest), TestPriority(500)]
        public async Task ApproveAllApplications() {
            Skip.If(!_fixture.RegistrationOk);
            foreach (var application in _applicationTestSet) {
                // approve app
                var applicationModel = await _applicationsDatabase.ApproveApplicationAsync(application.Model.ApplicationId.ToString(), true, true);
                Assert.NotNull(applicationModel);
                Assert.Equal(ApplicationState.Approved, applicationModel.State);
            }
        }

        /// <summary>
        /// Create a NewKeyPair request for all applications.
        /// </summary>
        [SkippableFact, Trait(Constants.Type, Constants.UnitTest), TestPriority(1000)]
        public async Task NewKeyPairRequestAllApplications() {
            Skip.If(!_fixture.RegistrationOk);
            var count = 0;
            foreach (var application in _applicationTestSet) {
                var groups = await _certificateGroup.GetGroupIdsAsync();
                foreach (var group in groups) {
                    var applicationId = application.Model.ApplicationId.ToString();
                    var requestId = await _certificateRequest.StartNewKeyPairRequestAsync(new CreateNewKeyPairRequestModel {
                        ApplicationId = applicationId,
                        CertificateGroupId = group,
                        SubjectName = application.Subject,
                        DomainNames = application.DomainNames.ToArray(),
                        PrivateKeyFormat = application.PrivateKeyFormat,
                        PrivateKeyPassword = application.PrivateKeyPassword,
                        CertificateTypeId = null
                    }, "unittest@opcvault.com");
                    Assert.NotNull(requestId);
                    // read request
                    var request = await _certificateRequest.ReadAsync(requestId);
                    Assert.Equal(CertificateRequestState.New, request.State);
                    Assert.Equal(requestId, request.RequestId);
                    Assert.Equal(applicationId, request.ApplicationId);
                    Assert.False(request.SigningRequest);
                    Assert.True(Opc.Ua.Utils.CompareDistinguishedName(application.Subject, request.SubjectName));
                    Assert.Equal(group, request.CertificateGroupId);
                    //Assert.Equal(null, fullRequest.CertificateTypeId);
                    Assert.Equal(application.DomainNames.ToArray(), request.DomainNames);
                    Assert.Equal(application.PrivateKeyFormat, request.PrivateKeyFormat);

                    // TODO: test all fields
                    application.RequestIds.Add(requestId);
                    count++;
                }
            }
            Assert.True(count > 0);
        }

        /// <summary>
        /// Create a Certificate Signing Request for all applications.
        /// </summary>
        [SkippableFact, Trait(Constants.Type, Constants.UnitTest), TestPriority(1000)]
        public async Task SigningRequestAllApplications() {
            Skip.If(!_fixture.RegistrationOk);
            var count = 0;
            foreach (var application in _applicationTestSet) {
                var groups = await _certificateGroup.GetGroupIdsAsync();
                foreach (var group in groups) {
                    var applicationId = application.Model.ApplicationId.ToString();
                    var certificateGroupConfiguration = await _certificateGroup.GetGroupConfigurationAsync(group);
                    var csrCertificate = CertificateFactory.CreateCertificate(
                        null, null, null,
                        application.ApplicationRecord.ApplicationUri,
                        null,
                        application.Subject,
                        application.DomainNames.ToArray(),
                        certificateGroupConfiguration.DefaultCertificateKeySize,
                        DateTime.UtcNow.AddDays(-20),
                        certificateGroupConfiguration.DefaultCertificateLifetime,
                        certificateGroupConfiguration.DefaultCertificateHashSize
                        );
                    var csr = CertificateFactory.CreateSigningRequest(
                        csrCertificate,
                        application.DomainNames);
                    var requestId = await _certificateRequest.StartSigningRequestAsync(new CreateSigningRequestModel {
                            ApplicationId = applicationId,
                            CertificateGroupId = group,
                            CertificateRequest = csr,
                            CertificateTypeId = null
                        }, "unittest@opcvault.com");
                    Assert.NotNull(requestId);
                    // read request
                    var request = await _certificateRequest.ReadAsync(requestId);
                    Assert.Equal(CertificateRequestState.New, request.State);
                    Assert.Null(request.PrivateKeyFormat);
                    Assert.True(request.SigningRequest);
                    Assert.Equal(requestId, request.RequestId);
                    Assert.Equal(applicationId, request.ApplicationId);
                    Assert.Null(request.SubjectName);
                    Assert.Equal(group, request.CertificateGroupId);
                    //Assert.Equal(null, fullRequest.CertificateTypeId);
                    //Assert.Equal(application.DomainNames.ToArray(), fullRequest.DomainNames);
                    Assert.Null(request.PrivateKeyFormat);
                    // add to list
                    application.RequestIds.Add(requestId);
                    count++;
                }
            }
            Assert.True(count > 0);
        }

        /// <summary>
        /// Fetch the certificate requests for all applications after StartRequests.
        /// </summary>
        [SkippableFact, Trait(Constants.Type, Constants.UnitTest), TestPriority(1400)]
        public async Task FetchRequestsAfterStartAllApplications() {
            await FetchRequestsAllApplications();
        }


        /// <summary>
        /// Read certificate requests for all applications.
        /// </summary>
        [SkippableFact, Trait(Constants.Type, Constants.UnitTest), TestPriority(1500)]
        public async Task ReadRequestsAllApplications() {
            Skip.If(!_fixture.RegistrationOk);
            foreach (var application in _applicationTestSet) {
                foreach (var requestId in application.RequestIds) {
                    var request = await _certificateRequest.ReadAsync(requestId);
                    Assert.Equal(CertificateRequestState.New, request.State);
                }
            }
        }


        /// <summary>
        /// Approve or reject certificate requests for all applications.
        /// </summary>
        [SkippableFact, Trait(Constants.Type, Constants.UnitTest), TestPriority(2000)]
        public async Task ApproveRequestsAllApplications() {
            Skip.If(!_fixture.RegistrationOk);
            foreach (var application in _applicationTestSet) {
                foreach (var requestId in application.RequestIds) {
                    var request = await _certificateRequest.ReadAsync(requestId);
                    Assert.Equal(CertificateRequestState.New, request.State);
                    // approve/reject 50% randomly
                    var reject = _randomSource.NextInt32(100) > 50;
                    if (!reject) {
                        await _certificateRequest.ApproveAsync(requestId);
                    }
                    else {
                        await _certificateRequest.RejectAsync(requestId);
                    }
                    request = await _certificateRequest.ReadAsync(requestId);
                    Assert.Equal(reject ? CertificateRequestState.Rejected : CertificateRequestState.Approved, request.State);
                }
            }
        }

        /// <summary>
        /// Fetch the certificate requests for all applications after Approve.
        /// </summary>
        [SkippableFact, Trait(Constants.Type, Constants.UnitTest), TestPriority(2000)]
        public async Task FetchRequestsAfterApproveAllApplications() {
            await FetchRequestsAllApplications();
        }

        /// <summary>
        /// Accept the certificate requests for all applications.
        /// </summary>
        [SkippableFact, Trait(Constants.Type, Constants.UnitTest), TestPriority(3000)]
        public async Task AcceptRequestsAllApplications() {
            Skip.If(!_fixture.RegistrationOk);
            foreach (var application in _applicationTestSet) {
                foreach (var requestId in application.RequestIds) {
                    var appModel = application.Model;
                    var applicationId = application.Model.ApplicationId.ToString();
                    var request = await _certificateRequest.ReadAsync(requestId);
                    if (request.State == CertificateRequestState.Approved) {
                        await _certificateRequest.AcceptAsync(requestId);
                        request = await _certificateRequest.ReadAsync(requestId);
                        Assert.Equal(CertificateRequestState.Accepted, request.State);
                    }
                    else {
                        await Assert.ThrowsAsync<ResourceInvalidStateException>(() => _certificateRequest.AcceptAsync(requestId));
                    }
                }
            }
        }

        /// <summary>
        /// Fetch the certificate requests for all applications after Approve.
        /// </summary>
        [SkippableFact, Trait(Constants.Type, Constants.UnitTest), TestPriority(3100)]
        public async Task FetchRequestsAfterAcceptAllApplications() {
            await FetchRequestsAllApplications();
        }


        /// <summary>
        /// Delete the certificate requests for all applications.
        /// </summary>
        [SkippableFact, Trait(Constants.Type, Constants.UnitTest), TestPriority(4000)]
        public async Task DeleteRequestsHalfApplications() {
            Skip.If(!_fixture.RegistrationOk);
            foreach (var application in _applicationTestSet) {
                foreach (var requestId in application.RequestIds) {
                    if (_randomSource.NextInt32(100) > 50) {
                        var request = await _certificateRequest.ReadAsync(requestId);
                        if (request.State == CertificateRequestState.New ||
                            request.State == CertificateRequestState.Rejected ||
                            request.State == CertificateRequestState.Approved ||
                            request.State == CertificateRequestState.Accepted) {
                            await _certificateRequest.DeleteAsync(requestId);
                        }
                        else {
                            await Assert.ThrowsAsync<ResourceInvalidStateException>(() => _certificateRequest.DeleteAsync(requestId));
                        }
                    }
                }
            }
        }

        /// <summary>
        /// Fetch the certificate requests for all applications after Approve.
        /// </summary>
        [SkippableFact, Trait(Constants.Type, Constants.UnitTest), TestPriority(4500)]
        public async Task FetchRequestsAfterDeleteHalfApplications() {
            await FetchRequestsAllApplications();
        }


        /// <summary>
        /// Revoke the certificate requests for all deleted applications.
        /// </summary>
        [SkippableFact, Trait(Constants.Type, Constants.UnitTest), TestPriority(5000)]
        public async Task RevokeRequestsAllApplications() {
            Skip.If(!_fixture.RegistrationOk);
            foreach (var application in _applicationTestSet) {
                foreach (var requestId in application.RequestIds) {
                    var request = await _certificateRequest.ReadAsync(requestId);
                    if (request.State == CertificateRequestState.Deleted) {
                        await _certificateRequest.RevokeAsync(requestId);
                    }
                }
            }
        }

        /// <summary>
        /// Fetch the certificate requests for all applications after Approve.
        /// </summary>
        [SkippableFact, Trait(Constants.Type, Constants.UnitTest), TestPriority(5100)]
        public async Task FetchRequestsAfterRevokeAllApplications() {
            await FetchRequestsAllApplications();
        }


        /// <summary>
        /// Delete the certificate requests for all applications.
        /// </summary>
        [SkippableFact, Trait(Constants.Type, Constants.UnitTest), TestPriority(5400)]
        public async Task DeleteRequestsAllApplications() {
            Skip.If(!_fixture.RegistrationOk);
            foreach (var application in _applicationTestSet) {
                foreach (var requestId in application.RequestIds) {
                    var request = await _certificateRequest.ReadAsync(requestId);
                    if (request.State == CertificateRequestState.New ||
                        request.State == CertificateRequestState.Rejected ||
                        request.State == CertificateRequestState.Approved ||
                        request.State == CertificateRequestState.Accepted) {
                        await _certificateRequest.DeleteAsync(requestId);
                    }
                    else {
                        await Assert.ThrowsAsync<ResourceInvalidStateException>(() => _certificateRequest.DeleteAsync(requestId));
                    }
                }
            }
        }

        /// <summary>
        /// Fetch the certificate requests for all applications after Approve.
        /// </summary>
        [SkippableFact, Trait(Constants.Type, Constants.UnitTest), TestPriority(5500)]
        public async Task FetchRequestsAfterDeleteAllApplications() {
            await FetchRequestsAllApplications();
        }


        /// <summary>
        /// RevokeGroup the certificate requests for all applications.
        /// </summary>
        [SkippableFact, Trait(Constants.Type, Constants.UnitTest), TestPriority(5600)]
        public async Task RevokeGroupRequestsAllApplications() {
            Skip.If(!_fixture.RegistrationOk);
            var groups = await _certificateGroup.GetGroupIdsAsync();
            foreach (var group in groups) {
                await _certificateRequest.RevokeGroupAsync(group, true);
            }
        }

        /// <summary>
        /// Fetch the certificate requests for all applications after Approve.
        /// </summary>
        [SkippableFact, Trait(Constants.Type, Constants.UnitTest), TestPriority(5700)]
        public async Task FetchRequestsAfterRevokeGroupAllApplications() {
            await FetchRequestsAllApplications();
        }


        /// <summary>
        /// Purge the certificate requests for all applications.
        /// </summary>
        [SkippableFact, Trait(Constants.Type, Constants.UnitTest), TestPriority(5800)]
        public async Task PurgeRequestsAllApplications() {
            Skip.If(!_fixture.RegistrationOk);
            foreach (var application in _applicationTestSet) {
                foreach (var requestId in application.RequestIds) {
                    var request = await _certificateRequest.ReadAsync(requestId);
                    if (request.State == CertificateRequestState.Revoked ||
                        request.State == CertificateRequestState.Rejected ||
                        request.State == CertificateRequestState.Removed ||
                        request.State == CertificateRequestState.New) {
                        await _certificateRequest.PurgeAsync(requestId);
                    }
                    else {
                        await Assert.ThrowsAsync<ResourceInvalidStateException>(() => _certificateRequest.PurgeAsync(requestId));
                    }
                }
            }
        }

        /// <summary>
        /// Fetch the certificate requests for all applications after Purge.
        /// </summary>
        [SkippableFact, Trait(Constants.Type, Constants.UnitTest), TestPriority(5900)]
        public async Task FetchRequestsAfterPurgeAllApplications() {
            await FetchRequestsAllApplications(true);
        }

        /// <summary>
        /// Unregister all applications, clean up test set.
        /// </summary>
        /// <returns></returns>
        [SkippableFact, Trait(Constants.Type, Constants.UnitTest), TestPriority(6000)]
        public async Task UnregisterAllApplications() {
            Skip.If(!_fixture.RegistrationOk);
            foreach (var application in _applicationTestSet) {
                var applicationModel = await _applicationsDatabase.UnregisterApplicationAsync(application.Model.ApplicationId.ToString());
                Assert.NotNull(applicationModel);
                Assert.NotNull(applicationModel.ApplicationId);
            }
        }

        /// <summary>
        /// Delete the application test set.
        /// </summary>
        /// <returns></returns>
        [SkippableFact, Trait(Constants.Type, Constants.UnitTest), TestPriority(9000)]
        public async Task DeleteAllApplications() {
            Skip.If(!_fixture.RegistrationOk);
            foreach (var application in _applicationTestSet) {
                await _applicationsDatabase.DeleteApplicationAsync(application.Model.ApplicationId.ToString(), false);
            }
        }


        /// <summary>
        /// Test helper to test fetch for various states of requests in the workflow.
        /// </summary>
        private async Task FetchRequestsAllApplications(bool purged = false) {
            Skip.If(!_fixture.RegistrationOk);
            foreach (var application in _applicationTestSet) {
                foreach (var requestId in application.RequestIds) {
                    var appModel = application.Model;
                    var applicationId = application.Model.ApplicationId.ToString();
                    if (purged) {
                        await Assert.ThrowsAsync<ResourceNotFoundException>(() => _certificateRequest.FetchRequestAsync(requestId, applicationId));
                        continue;
                    }
                    var fetchResult = await _certificateRequest.FetchRequestAsync(requestId, applicationId);
                    Assert.Equal(requestId, fetchResult.RequestId);
                    Assert.Equal(applicationId, fetchResult.ApplicationId);
                    if (fetchResult.State == CertificateRequestState.Approved ||
                        fetchResult.State == CertificateRequestState.Accepted) {
                        if (fetchResult.PrivateKey != null) {
                            Assert.Equal(application.PrivateKeyFormat, fetchResult.PrivateKeyFormat);
                        }
                        Assert.NotNull(fetchResult.SignedCertificate);
                        if (fetchResult.PrivateKey != null) {
                            Assert.NotNull(fetchResult.PrivateKey);
                        }
                        else {
                            Assert.Null(fetchResult.PrivateKey);
                        }
                    }
                    else
                    if (fetchResult.State == CertificateRequestState.Revoked ||
                        fetchResult.State == CertificateRequestState.Deleted) {
                        Assert.Null(fetchResult.PrivateKey);
                    }
                    else if (fetchResult.State == CertificateRequestState.Rejected ||
                        fetchResult.State == CertificateRequestState.New ||
                        fetchResult.State == CertificateRequestState.Removed
                        ) {
                        Assert.Null(fetchResult.PrivateKey);
                        Assert.Null(fetchResult.SignedCertificate);
                    }
                    else {
                        Assert.True(false, "Invalid State");
                    }
                }
            }
        }

        private readonly CertificateAuthorityTestFixture _fixture;
        private readonly ILogger _logger;
        private readonly IApplicationsDatabase _applicationsDatabase;
        private readonly IVaultClient _certificateGroup;
        private readonly ICertificateAuthority _certificateRequest;
        private readonly IList<ApplicationTestData> _applicationTestSet;
        private readonly RandomSource _randomSource;
    }
}
