// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace Microsoft.Azure.IIoT.OpcUa.Twin {
    using Microsoft.Azure.IIoT.OpcUa.Exceptions;
    using Microsoft.Azure.IIoT.OpcUa.Registry;
    using Microsoft.Azure.IIoT.OpcUa.Models;
    using Microsoft.Azure.IIoT.Diagnostics;
    using Microsoft.Azure.IIoT.Hub;
    using Microsoft.Azure.IIoT.Hub.Models;
    using Newtonsoft.Json;
    using Newtonsoft.Json.Linq;
    using System;
    using System.Linq;
    using System.Threading;
    using System.Threading.Tasks;

    /// <summary>
    /// Implements node and publish services through edge command control against
    /// the OPC UA edge device module receiving service requests via device method
    /// call.
    /// </summary>
    public sealed class OpcUaTwinValidator : IOpcUaValidationServices {

        /// <summary>
        /// Create service
        /// </summary>
        /// <param name="jobs"></param>
        /// <param name="logger"></param>
        public OpcUaTwinValidator(IIoTHubJobServices jobs, ILogger logger) {
            _jobs = jobs ?? throw new ArgumentNullException(nameof(jobs));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        /// <summary>
        /// Discovery application model using the provided discovery url
        /// </summary>
        /// <param name="discoveryUrl"></param>
        /// <returns></returns>
        public async Task<ApplicationRegistrationModel> DiscoverApplicationAsync(
            Uri discoveryUrl) {
            if (discoveryUrl == null) {
                throw new ArgumentNullException(nameof(discoveryUrl));
            }
            return await CallServiceOnAllSupervisors<Uri, ApplicationRegistrationModel>(
                "DiscoverApplication_V1", discoveryUrl, kValidationTimeout);
        }

        /// <summary>
        /// Validate request
        /// </summary>
        /// <param name="endpoint"></param>
        /// <returns></returns>
        public async Task<ApplicationRegistrationModel> ValidateEndpointAsync(
            EndpointModel endpoint) {
            if (endpoint == null) {
                throw new ArgumentNullException(nameof(endpoint));
            }
            return await CallServiceOnAllSupervisors<EndpointModel, ApplicationRegistrationModel>(
                "ValidateEndpoint_V1", endpoint, kValidationTimeout);
        }

        /// <summary>
        /// Calls service on all controllers until a successful response is returned
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <typeparam name="R"></typeparam>
        /// <param name="service"></param>
        /// <param name="request"></param>
        /// <returns></returns>
        private async Task<R> CallServiceOnAllSupervisors<T, R>(
            string service, T request, TimeSpan timeout) {

            // Create job to all supervisors - see edge service program.cs
            var jobId = Guid.NewGuid().ToString();
            var job = await _jobs.CreateAsync(new JobModel {
                JobId = jobId,
                QueryCondition = "FROM devices.modules WHERE " +
                    $"properties.reported.{OpcUaTwinRegistration.kTypeProp} = 'supervisor'",
                Type = JobType.ScheduleDeviceMethod,
                MaxExecutionTimeInSeconds = timeout.Seconds,
                MethodParameter = new MethodParameterModel {
                    Name = service,
                    JsonPayload = JsonConvertEx.SerializeObject(request)
                }
            });
            _logger.Info($"Job {jobId} created...", () => job.Status);
            var tryCancel = true;
            try {
                // Poll to completion
                var cts = new CancellationTokenSource(timeout);
                while (true) {
                    if (!string.IsNullOrEmpty(job.FailureReason)) {
                        throw new MethodCallException(job.FailureReason);
                    }
                    var responses = job.Devices
                        .Where(d => d.Status == DeviceJobStatus.Completed &&
                            d.Outcome != null)
                        .Where(d => {
                            if (d.Outcome.Status != 200) {
                                _logger.Debug($"{d.DeviceId} responded with {d.Outcome.Status}!",
                                    () => JToken.Parse(d.Outcome.JsonPayload));
                                return false; // Skip
                            }
                            return true;
                        })
                        .Select(d => JsonConvertEx.DeserializeObject<R>(d.Outcome.JsonPayload));
                    if (job.Status == JobStatus.Completed ||
                        job.Status == JobStatus.Failed ||
                        job.Status == JobStatus.Cancelled ||
                        job.Status == JobStatus.Running) {
                        tryCancel = false;
                    }
                    if (responses.Any()) {
                        _logger.Info($"Job {jobId} done - response received!", () => job.Status);
                        return responses.First();
                    }
                    if (cts.IsCancellationRequested ||
                        job.Status == JobStatus.Completed ||
                        job.Status == JobStatus.Failed ||
                        job.Status == JobStatus.Cancelled) {
                        break;
                    }
                    job = await _jobs.RefreshAsync(jobId);
                    _logger.Info($"Job {jobId} polled...", () => job.Status);
                }
                throw new TimeoutException(
                    $"No response received for job {jobId} after {timeout}.");
            }
            finally {
                if (tryCancel) {
                    // Clean up
                    try {
                        await _jobs.CancelAsync(jobId);
                    }
                    catch (Exception ex) {
                        _logger.Warn($"Failed to cancel job {jobId}.", () => ex);
                    }
                }
            }
        }

        private readonly IIoTHubJobServices _jobs;
        private readonly ILogger _logger;

        private static readonly TimeSpan kValidationTimeout = TimeSpan.FromSeconds(30);
    }
}