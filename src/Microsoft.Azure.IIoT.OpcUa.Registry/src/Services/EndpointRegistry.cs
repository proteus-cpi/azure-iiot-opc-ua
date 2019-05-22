// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace Microsoft.Azure.IIoT.OpcUa.Registry.Services {
    using Microsoft.Azure.IIoT.OpcUa.Registry.Models;
    using Microsoft.Azure.IIoT.Exceptions;
    using Microsoft.Azure.IIoT.Http;
    using Microsoft.Azure.IIoT.Hub;
    using Microsoft.Azure.IIoT.Hub.Models;
    using Microsoft.Azure.IIoT.Utils;
    using Newtonsoft.Json.Linq;
    using Serilog;
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Threading.Tasks;
    using System.Collections.Concurrent;

    /// <summary>
    /// Endpoint registry services using the IoT Hub twin services for endpoint
    /// identity registration/retrieval.  
    /// </summary>
    public sealed class EndpointRegistry : IEndpointRegistry, IEndpointRegistry2,
        IEndpointBulkProcessor, IApplicationRegistryListener, IEndpointRegistryEvents, 
        IDisposable {

        /// <summary>
        /// Create endpoint registry
        /// </summary>
        /// <param name="iothub"></param>
        /// <param name="events"></param>
        /// <param name="activate"></param>
        /// <param name="logger"></param>
        public EndpointRegistry(IIoTHubTwinServices iothub, IApplicationRegistryEvents events,
            IActivationServices<EndpointRegistrationModel> activate, ILogger logger) {
            _iothub = iothub ?? throw new ArgumentNullException(nameof(iothub));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _activator = activate ?? throw new ArgumentNullException(nameof(activate));
            _listeners = new ConcurrentDictionary<string, IEndpointRegistryListener>();

            // Register for application registry events
            _unregister = events.Register(this);
        }

        /// <inheritdoc/>
        public void Dispose() {
            _unregister?.Invoke();
        }

        /// <inheritdoc/>
        public Action Register(IEndpointRegistryListener listener) {
            var token = Guid.NewGuid().ToString();
            _listeners.TryAdd(token, listener);
            return () => _listeners.TryRemove(token, out var _);
        }

        /// <inheritdoc/>
        public async Task<EndpointInfoModel> GetEndpointAsync(string id,
            bool onlyServerState) {
            if (string.IsNullOrEmpty(id)) {
                throw new ArgumentException(nameof(id));
            }
            var device = await _iothub.GetAsync(id);
            return TwinModelToEndpointRegistrationModel(device, onlyServerState, false);
        }

        /// <inheritdoc/>
        public async Task<EndpointInfoListModel> ListEndpointsAsync(string continuation,
            bool onlyServerState, int? pageSize) {
            // Find all devices where endpoint information is configured
            var query = $"SELECT * FROM devices WHERE " +
                $"tags.{nameof(BaseRegistration.DeviceType)} = 'Endpoint' " +
                $"AND NOT IS_DEFINED(tags.{nameof(BaseRegistration.NotSeenSince)})";
            var devices = await _iothub.QueryDeviceTwinsAsync(query, continuation, pageSize);

            return new EndpointInfoListModel {
                ContinuationToken = devices.ContinuationToken,
                Items = devices.Items
                    .Select(d => TwinModelToEndpointRegistrationModel(d, onlyServerState, true))
                    .Where(x => x != null)
                    .ToList()
            };
        }

        /// <inheritdoc/>
        public async Task<EndpointInfoListModel> QueryEndpointsAsync(
            EndpointRegistrationQueryModel model, bool onlyServerState, int? pageSize) {

            var query = "SELECT * FROM devices WHERE " +
                $"tags.{nameof(EndpointRegistration.DeviceType)} = 'Endpoint' ";

            if (!(model?.IncludeNotSeenSince ?? false)) {
                // Scope to non deleted twins
                query += $"AND NOT IS_DEFINED(tags.{nameof(BaseRegistration.NotSeenSince)}) ";
            }
            if (model?.Url != null) {
                // If Url provided, include it in search
                query += $"AND tags.{nameof(EndpointRegistration.EndpointUrlLC)} = " +
                    $"'{model.Url.ToLowerInvariant()}' ";
            }
            if (model?.Certificate != null) {
                // If cert provided, include it in search
                query += $"AND tags.{nameof(BaseRegistration.Thumbprint)} = " +
                    $"{model.Certificate.ToSha1Hash()} ";
            }
            if (model?.SecurityMode != null) {
                // If SecurityMode provided, include it in search
                query += $"AND properties.desired.{nameof(EndpointRegistration.SecurityMode)} = " +
                    $"'{model.SecurityMode}' ";
            }
            if (model?.SecurityPolicy != null) {
                // If SecurityPolicy uri provided, include it in search
                query += $"AND properties.desired.{nameof(EndpointRegistration.SecurityPolicy)} = " +
                    $"'{model.SecurityPolicy}' ";
            }
            if (model?.UserAuthentication != null) {
                // If TokenType provided, include it in search
                if (model.UserAuthentication.Value != CredentialType.None) {
                    query += $"AND properties.desired.{nameof(EndpointRegistration.CredentialType)} = " +
                            $"'{model.UserAuthentication}' ";
                }
                else {
                    query += $"AND (properties.desired.{nameof(EndpointRegistration.CredentialType)} = " +
                            $"'{model.UserAuthentication}' " +
                        $"OR NOT IS_DEFINED(tags.{nameof(EndpointRegistration.CredentialType)})) ";
                }
            }
            if (model?.Connected != null) {
                // If flag provided, include it in search
                if (model.Connected.Value) {
                    query += $"AND connectionState = 'Connected' ";
                        // Do not use connected property as module might have exited before updating.
                }
                else {
                    query += $"AND (connectionState = 'Disconnected' " +
                        $"OR properties.reported.{TwinProperty.kConnected} != true) ";
                }
            }
            if (model?.Activated != null) {
                // If flag provided, include it in search
                if (model.Activated.Value) {
                    query += $"AND tags.{nameof(EndpointRegistration.Activated)} = true ";
                }
                else {
                    query += $"AND (tags.{nameof(EndpointRegistration.Activated)} != true " +
                        $"OR NOT IS_DEFINED(tags.{nameof(EndpointRegistration.Activated)})) ";
                }
            }
            if (model?.EndpointState != null) {
                query += $"AND properties.reported.{nameof(EndpointRegistration.State)} = " +
                    $"'{model.EndpointState}' ";
            }
            var result = await _iothub.QueryDeviceTwinsAsync(query, null, pageSize);
            return new EndpointInfoListModel {
                ContinuationToken = result.ContinuationToken,
                Items = result.Items
                    .Select(t => EndpointRegistration.FromTwin(t, onlyServerState))
                    .Select(s => s.ToServiceModel())
                    .ToList()
            };
        }

        /// <inheritdoc/>
        public async Task UpdateEndpointAsync(string endpointId,
            EndpointRegistrationUpdateModel request) {
            if (request == null) {
                throw new ArgumentNullException(nameof(request));
            }
            if (string.IsNullOrEmpty(endpointId)) {
                throw new ArgumentException(nameof(endpointId));
            }

            // Get existing endpoint and compare to see if we need to patch.
            var twin = await _iothub.GetAsync(endpointId);
            if (twin.Id != endpointId) {
                throw new ArgumentException("Id must be same as twin to patch",
                    nameof(endpointId));
            }

            // Convert to twin registration
            var registration = BaseRegistration.ToRegistration(twin, true)
                as EndpointRegistration;
            if (registration == null) {
                throw new ResourceNotFoundException(
                    $"{endpointId} is not a endpoint registration.");
            }

            // Update registration from update request
            var patched = registration.ToServiceModel();

            var duplicate = false;
            if (request.User != null) {
                patched.Registration.Endpoint.User = new CredentialModel();

                if (request.User.Type != null) {
                    // Change token type?  Always duplicate since id changes.
                    duplicate = request.User.Type !=
                        patched.Registration.Endpoint.User.Type;

                    patched.Registration.Endpoint.User.Type =
                        (CredentialType)request.User.Type;
                }
                if ((patched.Registration.Endpoint.User.Type
                    ?? CredentialType.None) != CredentialType.None) {
                    patched.Registration.Endpoint.User.Value =
                        request.User.Value;
                }
                else {
                    patched.Registration.Endpoint.User.Value = null;
                }
            }

            // Patch
            await _iothub.CreateOrUpdateAsync(EndpointRegistration.Patch(
                duplicate ? null : registration,
                EndpointRegistration.FromServiceModel(patched, registration.IsDisabled)));
                        // To have duplicate item disabled, too if needed
        }

        /// <inheritdoc/>
        public async Task ActivateEndpointAsync(string id) {
            if (string.IsNullOrEmpty(id)) {
                throw new ArgumentException(nameof(id));
            }

            // Get existing endpoint and compare to see if we need to patch.
            var twin = await _iothub.GetAsync(id);
            if (twin.Id != id) {
                throw new ArgumentException("Id must be same as twin to activate",
                    nameof(id));
            }

            // Convert to twin registration
            var registration = BaseRegistration.ToRegistration(twin, true)
                as EndpointRegistration;
            if (registration == null) {
                throw new ResourceNotFoundException(
                    $"{id} is not an activatable endpoint registration.");
            }
            if (string.IsNullOrEmpty(registration.SupervisorId)) {
                throw new ArgumentException($"Twin {id} not registered with a supervisor.");
            }

            if (!(registration.Activated ?? false)) {
                var patched = registration.ToServiceModel();
                patched.ActivationState = EndpointActivationState.Activated;

                // Update supervisor settings
                var secret = await _iothub.GetPrimaryKeyAsync(registration.DeviceId);
                try {
                    // Call down to supervisor to activate - this can fail
                    await _activator.ActivateEndpointAsync(patched.Registration, secret);

                    // Update supervisor desired properties
                    await SetSupervisorTwinSecretAsync(registration.SupervisorId,
                        registration.DeviceId, secret);
                    // Write twin activation status in twin settings
                    await _iothub.CreateOrUpdateAsync(EndpointRegistration.Patch(
                        registration, EndpointRegistration.FromServiceModel(patched,
                            registration.IsDisabled)));
                }
                catch (Exception ex) {
                    // Undo activation
                    await Try.Async(() => _activator.DeactivateEndpointAsync(
                        patched.Registration));
                    await Try.Async(() => SetSupervisorTwinSecretAsync(
                        registration.SupervisorId, registration.DeviceId, null));
                    _logger.Error(ex, "Failed to activate twin");
                    throw ex;
                }
            }
        }

        /// <inheritdoc/>
        public async Task DeactivateEndpointAsync(string id) {
            if (string.IsNullOrEmpty(id)) {
                throw new ArgumentException(nameof(id));
            }
            // Get existing endpoint and compare to see if we need to patch.
            var twin = await _iothub.GetAsync(id);
            if (twin.Id != id) {
                throw new ArgumentException("Id must be same as twin to deactivate",
                    nameof(id));
            }
            // Convert to twin registration
            var registration = BaseRegistration.ToRegistration(twin, true)
                as EndpointRegistration;
            if (registration == null) {
                throw new ResourceNotFoundException(
                    $"{id} is not an activatable endpoint registration.");
            }
            if (string.IsNullOrEmpty(registration.SupervisorId)) {
                throw new ArgumentException($"Twin {id} not registered with a supervisor.");
            }
            var patched = registration.ToServiceModel();

            // Deactivate twin in twin settings
            await SetSupervisorTwinSecretAsync(registration.SupervisorId,
                registration.DeviceId, null);
            // Call down to supervisor to ensure deactivation is complete
            await Try.Async(() => _activator.DeactivateEndpointAsync(patched.Registration));

            // Mark as deactivated
            if (registration.Activated ?? false) {
                patched.ActivationState = EndpointActivationState.Deactivated;
                await _iothub.CreateOrUpdateAsync(EndpointRegistration.Patch(
                    registration, EndpointRegistration.FromServiceModel(patched,
                        registration.IsDisabled)));
            }
        }

        /// <inheritdoc/>
        public Task OnApplicationNewAsync(ApplicationInfoModel application) => 
            Task.CompletedTask;

        /// <inheritdoc/>
        public Task OnApplicationUpdatedAsync(ApplicationInfoModel application) => 
            Task.CompletedTask;
        
        /// <inheritdoc/>
        public Task OnApplicationApprovedAsync(ApplicationInfoModel application) => 
            Task.CompletedTask;
        
        /// <inheritdoc/>
        public Task OnApplicationRejectedAsync(ApplicationInfoModel application) => 
            Task.CompletedTask;

        /// <inheritdoc/>
        public Task OnApplicationEnabledAsync(ApplicationInfoModel application) {

            // TODO : Should we re-activate the endpoint?
            return Task.CompletedTask;
        }

        /// <inheritdoc/>
        public async Task OnApplicationDisabledAsync(ApplicationInfoModel application) {
            // Disable endpoints
            var query = $"SELECT * FROM devices WHERE " +
                $"tags.{nameof(EndpointRegistration.ApplicationId)} = " +
                    $"'{application.ApplicationId}' AND " +
                $"tags.{nameof(BaseRegistration.DeviceType)} = 'Endpoint'";
            string continuation = null;
            do {
                var devices = await _iothub.QueryDeviceTwinsAsync(query, continuation);
                foreach (var twin in devices.Items) {
                    var endpoint = EndpointRegistration.FromTwin(twin, true);
                    if (endpoint.IsDisabled ?? false) {
                        continue;
                    }
                    try {
                        if (endpoint.Activated ?? false) {
                            if (!string.IsNullOrEmpty(endpoint.SupervisorId)) {
                                await SetSupervisorTwinSecretAsync(endpoint.SupervisorId,
                                    twin.Id, null);
                            }
                        }
                        await _iothub.CreateOrUpdateAsync(EndpointRegistration.Patch(
                            endpoint, EndpointRegistration.FromServiceModel(
                                endpoint.ToServiceModel(), true))); // Disable
                    }
                    catch (Exception ex) {
                        _logger.Debug(ex, "Failed disabling of twin {twin}", twin.Id);
                    }
                }
                continuation = devices.ContinuationToken;
            }
            while (continuation != null);
        }

        /// <inheritdoc/>
        public async Task<IEnumerable<EndpointInfoModel>> GetApplicationEndpoints(string applicationId,
            bool includeDeleted, bool filterInactiveTwins) {
            // Include deleted twins if the application itself is deleted.  Otherwise omit.
            var endpoints = await GetEndpointsAsync(applicationId, includeDeleted);
            return endpoints
                    .Where(e => !filterInactiveTwins || (e.Connected && (e.Activated ?? false)))
                    .Select(e => e.ToServiceModel());
        }

        /// <inheritdoc/>
        public async Task OnApplicationDeletedAsync(ApplicationInfoModel application) {
            // Get all endpoint registrations and for each one, call delete, if failure,
            // stop half way and throw and do not complete.
            var result = await GetEndpointsAsync(application.ApplicationId, true);
            foreach (var endpoint in result) {
                try {
                    if (!string.IsNullOrEmpty(endpoint.SupervisorId)) {
                        await SetSupervisorTwinSecretAsync(endpoint.SupervisorId,
                            endpoint.DeviceId, null);
                    }
                }
                catch (Exception ex) {
                    _logger.Debug(ex, "Failed unregistration of twin {deviceId}",
                        endpoint.DeviceId);
                }
                await _iothub.DeleteAsync(endpoint.DeviceId);
            }
        }

        /// <inheritdoc/>
        public async Task ProcessDiscoveryEventsAsync(IEnumerable<EndpointInfoModel> newEndpoints,
            DiscoveryResultModel context,
            string supervisorId, string applicationId, bool hardDelete) {

            if (newEndpoints == null) {
                throw new ArgumentNullException(nameof(newEndpoints));
            }

            var found = newEndpoints
                .Select(e => EndpointRegistration.FromServiceModel(e, false))
                .ToList();

            var existing = Enumerable.Empty<EndpointRegistration>();
            if (!string.IsNullOrEmpty(applicationId)) {
                // Merge with existing endpoints of the application
                existing = await GetEndpointsAsync(applicationId, true);
            }

            var remove = new HashSet<EndpointRegistration>(existing,
                EndpointRegistration.Logical);
            var add = new HashSet<EndpointRegistration>(found,
                EndpointRegistration.Logical);
            var unchange = new HashSet<EndpointRegistration>(existing,
                EndpointRegistration.Logical);
            var change = new HashSet<EndpointRegistration>(found,
                EndpointRegistration.Logical);

            unchange.IntersectWith(add);
            change.IntersectWith(remove);
            remove.ExceptWith(found);
            add.ExceptWith(existing);

            var added = 0;
            var updated = 0;
            var unchanged = 0;
            var removed = 0;

            // Remove or disable an endpoint
            foreach (var item in remove) {
                try {
                    // Only touch applications the supervisor owns.
                    if (item.SupervisorId == supervisorId) {
                        if (hardDelete) {
                            var device = await _iothub.GetAsync(item.DeviceId);
                            // First we update any supervisor registration
                            var existingEndpoint = EndpointRegistration.FromTwin(device, false);
                            if (!string.IsNullOrEmpty(existingEndpoint.SupervisorId)) {
                                await SetSupervisorTwinSecretAsync(existingEndpoint.SupervisorId,
                                    device.Id, null);
                            }
                            // Then hard delete...
                            await _iothub.DeleteAsync(item.DeviceId);
                        }
                        else if (!(item.IsDisabled ?? false)) {
                            await _iothub.CreateOrUpdateAsync(
                                EndpointRegistration.Patch(item,
                                    EndpointRegistration.FromServiceModel(
                                        item.ToServiceModel(), true)));
                        }
                        else {
                            unchanged++;
                            continue;
                        }
                        removed++;
                    }
                    else {
                        // Skip the ones owned by other supervisors
                        unchanged++;
                    }
                }
                catch (Exception ex) {
                    unchanged++;
                    _logger.Error(ex, "Exception during discovery removal.");
                }
            }

            // Update endpoints that were disabled
            foreach (var exists in unchange) {
                try {
                    if (exists.SupervisorId == supervisorId || (exists.IsDisabled ?? false)) {
                        // Get the new one we will patch over the existing one...
                        var patch = change.First(x =>
                            EndpointRegistration.Logical.Equals(x, exists));
                        await ApplyActivationFilterAsync(context.DiscoveryConfig?.ActivationFilter,
                            patch);
                        if (exists != patch) {
                            await _iothub.CreateOrUpdateAsync(EndpointRegistration.Patch(
                                exists, patch));
                            updated++;
                            continue;
                        }
                    }
                    unchanged++;
                }
                catch (Exception ex) {
                    unchanged++;
                    _logger.Error(ex, "Exception during update.");
                }
            }

            // Add endpoint
            foreach (var item in add) {
                try {
                    await ApplyActivationFilterAsync(context.DiscoveryConfig?.ActivationFilter,
                        item);
                    await _iothub.CreateOrUpdateAsync(EndpointRegistration.Patch(null, item));
                    added++;
                }
                catch (Exception ex) {
                    unchanged++;
                    _logger.Error(ex, "Exception during discovery addition.");
                }
            }

            if (added != 0 || removed != 0) {
                _logger.Information("processed endpoint results: {added} endpoints added, {updated} " +
                    "updated, {removed} removed or disabled, and {unchanged} unchanged.",
                    added, updated, removed, unchanged);
            }
        }

        /// <summary>
        /// Get all endpoints for application id
        /// </summary>
        /// <param name="applicationId"></param>
        /// <param name="includeDeleted"></param>
        /// <returns></returns>
        private async Task<IEnumerable<EndpointRegistration>> GetEndpointsAsync(
            string applicationId, bool includeDeleted) {
            // Find all devices where endpoint information is configured
            var query = $"SELECT * FROM devices WHERE " +
                $"tags.{nameof(EndpointRegistration.ApplicationId)} = " +
                    $"'{applicationId}' AND " +
                $"tags.{nameof(BaseRegistration.DeviceType)} = 'Endpoint' ";

            if (!includeDeleted) {
                query += $"AND NOT IS_DEFINED(tags.{nameof(BaseRegistration.NotSeenSince)})";
            }

            var result = new List<DeviceTwinModel>();
            string continuation = null;
            do {
                var devices = await _iothub.QueryDeviceTwinsAsync(query, null);
                result.AddRange(devices.Items);
                continuation = devices.ContinuationToken;
            }
            while (continuation != null);
            return result
                .Select(d => EndpointRegistration.FromTwin(d, false))
                .Where(r => r != null);
        }

        /// <summary>
        /// Apply activation filter
        /// </summary>
        /// <param name="filter"></param>
        /// <param name="endpoint"></param>
        /// <returns></returns>
        private async Task<string> ApplyActivationFilterAsync(
            EndpointActivationFilterModel filter, EndpointRegistration endpoint) {
            if (filter == null || endpoint == null) {
                return null;
            }

            // TODO: Get trust list entry and validate endpoint.Certificate

            var mode = endpoint.SecurityMode ?? SecurityMode.None;
            if (!mode.MatchesFilter(filter.SecurityMode ?? SecurityMode.Best)) {
                return null;
            }
            var policy = endpoint.SecurityPolicy;
            if (filter.SecurityPolicies != null) {
                if (!filter.SecurityPolicies.Any(p =>
                    p.EqualsIgnoreCase(endpoint.SecurityPolicy))) {
                    return null;
                }
            }
            try {
                // Get endpoint twin secret
                var secret = await _iothub.GetPrimaryKeyAsync(endpoint.DeviceId);

                // Try activate endpoint - if possible...
                await _activator.ActivateEndpointAsync(
                    endpoint.ToServiceModel().Registration, secret);

                // Mark in supervisor
                await SetSupervisorTwinSecretAsync(endpoint.SupervisorId,
                    endpoint.DeviceId, secret);
                endpoint.Activated = true;
                return secret;
            }
            catch (Exception ex) {
                _logger.Information(ex, "Failed activating {eeviceId} based off " +
                    "filter.  Manual activation required.", endpoint.DeviceId);
                return null;
            }
        }

        /// <summary>
        /// Enable or disable twin on supervisor
        /// </summary>
        /// <param name="supervisorId"></param>
        /// <param name="twinId"></param>
        /// <param name="secret"></param>
        /// <returns></returns>
        private async Task SetSupervisorTwinSecretAsync(string supervisorId,
            string twinId, string secret) {

            if (string.IsNullOrEmpty(twinId)) {
                throw new ArgumentNullException(nameof(twinId));
            }
            if (string.IsNullOrEmpty(supervisorId)) {
                return; // ok, no supervisor
            }
            var deviceId = SupervisorModelEx.ParseDeviceId(supervisorId, out var moduleId);
            if (secret == null) {
                // Remove from supervisor - this disconnects the device
                await _iothub.UpdatePropertyAsync(deviceId, moduleId, twinId, null);
                _logger.Information("Twin {twinId} deactivated on {supervisorId}.",
                    twinId, supervisorId);
            }
            else {
                // Update supervisor to start supervising this endpoint
                await _iothub.UpdatePropertyAsync(deviceId, moduleId, twinId, secret);
                _logger.Information("Twin {twinId} activated on {supervisorId}.",
                    twinId, supervisorId);
            }
        }

        /// <summary>
        /// Convert device twin registration property to registration model
        /// </summary>
        /// <param name="twin"></param>
        /// <param name="skipInvalid"></param>
        /// <param name="onlyServerState">Only desired should be returned
        /// this means that you will look at stale information.</param>
        /// <returns></returns>
        private static EndpointInfoModel TwinModelToEndpointRegistrationModel(
            DeviceTwinModel twin, bool onlyServerState, bool skipInvalid) {

            // Convert to twin registration
            var registration = BaseRegistration.ToRegistration(twin, onlyServerState)
                as EndpointRegistration;
            if (registration == null) {
                if (skipInvalid) {
                    return null;
                }
                throw new ResourceNotFoundException(
                    $"{twin.Id} is not a registered opc ua endpoint.");
            }
            return registration.ToServiceModel();
        }

        /// <summary>
        /// Call listeners
        /// </summary>
        /// <param name="evt"></param>
        /// <returns></returns>
        private Task NotifyAllAsync(Func<IEndpointRegistryListener, Task> evt) {
            return Task
                .WhenAll(_listeners.Select(l => evt(l.Value)).ToArray())
                .ContinueWith(t => Task.CompletedTask);
        }

        private readonly IActivationServices<EndpointRegistrationModel> _activator;
        private readonly Action _unregister;
        private readonly ConcurrentDictionary<string, IEndpointRegistryListener> _listeners;
        private readonly IIoTHubTwinServices _iothub;
        private readonly ILogger _logger;
    }
}
