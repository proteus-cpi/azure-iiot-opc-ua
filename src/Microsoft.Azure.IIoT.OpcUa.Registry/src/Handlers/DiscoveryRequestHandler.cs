// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace Microsoft.Azure.IIoT.OpcUa.Registry.Handlers {
    using Microsoft.Azure.IIoT.OpcUa.Registry.Clients;
    using Microsoft.Azure.IIoT.OpcUa.Registry.Models;
    using Microsoft.Azure.IIoT.OpcUa.Registry;
    using Microsoft.Azure.IIoT.Tasks;
    using Serilog;
    using Microsoft.Azure.IIoT.Hub;
    using Newtonsoft.Json;
    using System;
    using System.Text;
    using System.Threading.Tasks;

    /// <summary>
    /// Handles discovery requests received from the
    /// <see cref="OnboardingClient"/> instance and pushes them
    /// to the supervisor module.
    /// </summary>
    public sealed class DiscoveryRequestHandler : IDeviceEventHandler {

        /// <inheritdoc/>
        public string ContentType => ContentTypes.DiscoveryRequest;

        /// <summary>
        /// Create handler
        /// </summary>
        /// <param name="discovery"></param>
        /// <param name="processor"></param>
        /// <param name="logger"></param>
        public DiscoveryRequestHandler(IDiscoveryServices discovery,
            ITaskProcessor processor, ILogger logger) {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _discovery = discovery ?? throw new ArgumentNullException(nameof(discovery));
            _processor = processor ?? throw new ArgumentNullException(nameof(processor));
        }

        /// <inheritdoc/>
        public Task HandleAsync(string deviceId, string moduleId, byte[] payload,
            Func<Task> checkpoint) {
            if (OnboardingHelper.kId == deviceId.ToString()) {
                var json = Encoding.UTF8.GetString(payload);
                DiscoveryRequestModel request;
                try {
                    request = JsonConvertEx.DeserializeObject<DiscoveryRequestModel>(json);
                    _processor.TrySchedule(() => _discovery.DiscoverAsync(request), checkpoint);
                }
                catch (Exception ex) {
                    _logger.Error(ex, "Failed to convert registration {json}", json);
                }
            }
            return Task.CompletedTask;
        }

        /// <inheritdoc/>
        public Task OnBatchCompleteAsync() => Task.CompletedTask;

        private readonly ILogger _logger;
        private readonly IDiscoveryServices _discovery;
        private readonly ITaskProcessor _processor;
    }
}
