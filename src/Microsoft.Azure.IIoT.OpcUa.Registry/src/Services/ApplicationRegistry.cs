// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace Microsoft.Azure.IIoT.OpcUa.Registry.Services {
    using Microsoft.Azure.IIoT.OpcUa.Registry.Models;
    using Microsoft.Azure.IIoT.Exceptions;
    using Microsoft.Azure.IIoT.Hub;
    using Newtonsoft.Json.Linq;
    using Serilog;
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Threading.Tasks;

    /// <summary>
    /// Application registry service using the IoT Hub twin services for
    /// identity managment.
    /// </summary>
    public sealed class ApplicationRegistry : IApplicationRegistry, IApplicationRegistry2, 
        IApplicationBulkProcessor {

        /// <summary>
        /// Create registry services
        /// </summary>
        /// <param name="iothub"></param>
        /// <param name="endpoints"></param>
        /// <param name="bulk"></param>
        /// <param name="broker"></param>
        /// <param name="logger"></param>
        public ApplicationRegistry(IIoTHubTwinServices iothub, IEndpointRegistry2 endpoints, 
            IEndpointBulkProcessor bulk, IApplicationRegistryBroker broker, ILogger logger) {
            _iothub = iothub ?? throw new ArgumentNullException(nameof(iothub));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _bulk = bulk ?? throw new ArgumentNullException(nameof(bulk));
            _endpoints = endpoints ?? throw new ArgumentNullException(nameof(endpoints));
            _broker = broker ?? throw new ArgumentNullException(nameof(broker));
        }

        /// <inheritdoc/>
        public async Task<ApplicationRegistrationResultModel> RegisterApplicationAsync(
            ApplicationRegistrationRequestModel request) {
            if (request == null) {
                throw new ArgumentNullException(nameof(request));
            }
            if (request.ApplicationUri == null) {
                throw new ArgumentNullException(nameof(request.ApplicationUri));
            }

            var registration = ApplicationRegistration.FromServiceModel(
                new ApplicationInfoModel {
                    ApplicationName = request.ApplicationName,
                    LocalizedNames = request.LocalizedNames,
                    ProductUri = request.ProductUri,
                    DiscoveryUrls = request.DiscoveryUrls,
                    DiscoveryProfileUri = request.DiscoveryProfileUri,
                    ApplicationType = request.ApplicationType ?? ApplicationType.Server,
                    ApplicationUri = request.ApplicationUri,
                    Capabilities = request.Capabilities,
                    GatewayServerUri = request.GatewayServerUri,
                    SiteId = request.SiteId,
                    Created = new RegistryOperationModel {
                        AuthorityId = null, // TODO: Add authority Id
                        Time = DateTime.UtcNow
                    },
                    Approved = null,
                    Updated = null,
                    Certificate = null, RecordId = null,
                    ApplicationId = null,
                    State = ApplicationState.New,
                    NotSeenSince = DateTime.UtcNow,
                    SupervisorId = null, 
                    HostAddresses = null,
                });

            await _iothub.CreateAsync(
                ApplicationRegistration.Patch(null, registration));

            var application = registration.ToServiceModel();
            await _broker.NotifyAllAsync(l => l.OnApplicationNewAsync(application)); 
            // TODO:  Add authority id from context
            await _broker.NotifyAllAsync(l => l.OnApplicationEnabledAsync(application)); 
            // TODO:  Add authority id from context
            await _broker.NotifyAllAsync(l => l.OnApplicationApprovedAsync(application)); 
            // TODO:  Add authority id from context

            return new ApplicationRegistrationResultModel {
                Id = registration.ApplicationId
            };
        }

        /// <inheritdoc/>
        public async Task ApproveApplicationAsync(string applicationId, bool force) {
            var app = await UpdateApplicationStateAsync(applicationId, ApplicationState.Approved,
                s => s == null || s == ApplicationState.New || force, null); // TODO: Add authority id
            await _broker.NotifyAllAsync(l => l.OnApplicationApprovedAsync(app));
            // TODO:  Add authority id from context
        }

        /// <inheritdoc/>
        public async Task RejectApplicationAsync(string applicationId, bool force) {
            var app = await UpdateApplicationStateAsync(applicationId, ApplicationState.Rejected,
                s => s == null || s == ApplicationState.New || force, null); // TODO: Add authority id
            await _broker.NotifyAllAsync(l => l.OnApplicationRejectedAsync(app));
            // TODO:  Add authority id from context
        }

        /// <inheritdoc/>
        public async Task DisableApplicationAsync(string applicationId) {
            while (true) {
                try {
                    var registration = await GetApplicationRegistrationAsync(applicationId);
                    var application = registration.ToServiceModel();
                    // Disable application
                    if (!(registration.IsDisabled ?? false)) {
                        application.Updated = new RegistryOperationModel {
                            AuthorityId = null, // TODO:  Add authority id from context
                            Time = DateTime.UtcNow
                        };
                        application.NotSeenSince = DateTime.UtcNow;
                        await _iothub.PatchAsync(ApplicationRegistration.Patch(
                            registration, ApplicationRegistration.FromServiceModel(
                                registration.ToServiceModel(), true)));
                    }
                    await _broker.NotifyAllAsync(l => l.OnApplicationDisabledAsync(application));
                    // TODO:  Add authority id from context
                    break;
                }
                catch (ResourceOutOfDateException ex) {
                    // Retry create/update
                    _logger.Debug(ex, "Retry disabling application...");
                    continue;
                }
            }
        }

        /// <inheritdoc/>
        public async Task EnableApplicationAsync(string applicationId) {
            while (true) {
                try {
                    var registration = await GetApplicationRegistrationAsync(applicationId);
                    var application = registration.ToServiceModel();
                    // Disable application
                    if (registration.IsDisabled ?? false) {
                        application.Updated = new RegistryOperationModel {
                            AuthorityId = null, // TODO:  Add authority id from context
                            Time = DateTime.UtcNow
                        };
                        application.NotSeenSince = null;
                        await _iothub.PatchAsync(ApplicationRegistration.Patch(
                            registration, ApplicationRegistration.FromServiceModel(
                                registration.ToServiceModel(), false)));
                    }
                    await _broker.NotifyAllAsync(l => l.OnApplicationEnabledAsync(application));
                    // TODO:  Add authority id from context
                    break;
                }
                catch (ResourceOutOfDateException ex) {
                    // Retry create/update
                    _logger.Debug(ex, "Retry enabling application...");
                    continue;
                }
            }
        }

        /// <inheritdoc/>
        public async Task UpdateApplicationAsync(string applicationId,
            ApplicationRegistrationUpdateModel request) {
            if (request == null) {
                throw new ArgumentNullException(nameof(request));
            }
            while (true) {
                try {
                    var registration = await GetApplicationRegistrationAsync(applicationId);

                    // Update registration from update request
                    var patched = registration.ToServiceModel();
                    if (request.ApplicationName != null) {
                        patched.ApplicationName = string.IsNullOrEmpty(request.ApplicationName) ?
                            null : request.ApplicationName;
                    }
                    if (request.LocalizedNames != null) {
                        patched.LocalizedNames = request.LocalizedNames;
                    }
                    if (request.ProductUri != null) {
                        patched.ProductUri = string.IsNullOrEmpty(request.ProductUri) ?
                            null : request.ProductUri;
                    }
                    if (request.GatewayServerUri != null) {
                        patched.GatewayServerUri = string.IsNullOrEmpty(request.GatewayServerUri) ?
                            null : request.GatewayServerUri;
                    }
                    if (request.Certificate != null) {
                        patched.Certificate = request.Certificate.Length == 0 ?
                            null : request.Certificate;
                    }
                    if (request.Capabilities != null) {
                        patched.Capabilities = request.Capabilities.Count == 0 ?
                            null : request.Capabilities;
                    }
                    if (request.DiscoveryUrls != null) {
                        patched.DiscoveryUrls = request.DiscoveryUrls.Count == 0 ?
                            null : request.DiscoveryUrls;
                    }
                    if (request.DiscoveryProfileUri != null) {
                        patched.DiscoveryProfileUri = string.IsNullOrEmpty(request.DiscoveryProfileUri) ?
                            null : request.DiscoveryProfileUri;
                    }

                    patched.Updated = new RegistryOperationModel {
                        AuthorityId = null, // TODO:  Add authority id from context
                        Time = DateTime.UtcNow
                    };

                    // Patch
                    await _iothub.PatchAsync(ApplicationRegistration.Patch(
                        registration, ApplicationRegistration.FromServiceModel(patched)));

                    await _broker.NotifyAllAsync(l => l.OnApplicationUpdatedAsync(patched));
                    // TODO:  Add authority id from context
                    break;
                }
                catch (ResourceOutOfDateException ex) {
                    // Retry create/update
                    _logger.Debug(ex, "Retry enabling application...");
                    continue;
                }
            }
        }

        /// <inheritdoc/>
        public async Task<ApplicationRegistrationModel> GetApplicationAsync(
            string applicationId, bool filterInactiveTwins) {
            var registration = await GetApplicationRegistrationAsync(applicationId);
            var application = registration.ToServiceModel();
            var endpoints = await _endpoints.GetApplicationEndpoints(applicationId, 
                application.NotSeenSince != null, filterInactiveTwins);
            return new ApplicationRegistrationModel {
                Application = application,
                Endpoints = endpoints
                    .Select(ep => ep.Registration)
                    .ToList()
            }.SetSecurityAssessment();
        }

        /// <inheritdoc/>
        public Task<QueryApplicationsByIdResultModel> QueryApplicationsByIdAsync(
            QueryApplicationsByIdRequestModel request) {
            // TODO
            throw new NotImplementedException();
        }

        /// <inheritdoc/>
        public async Task<ApplicationInfoListModel> QueryApplicationsAsync(
            ApplicationRegistrationQueryModel model, int? pageSize) {

            var query = "SELECT * FROM devices WHERE " +
                $"tags.{nameof(ApplicationRegistration.DeviceType)} = 'Application' ";

            if (!(model?.IncludeNotSeenSince ?? false)) {
                // Scope to non deleted applications
                query += $"AND NOT IS_DEFINED(tags.{nameof(BaseRegistration.NotSeenSince)}) ";
            }

            if (model?.Locale != null) {
                if (model?.ApplicationName != null) {
                    // If application name provided, include it in search
                    query += $"AND tags.{nameof(ApplicationRegistration.LocalizedNames)}" +
                        $".{model.Locale} = '{model.ApplicationName}' ";
                }
                else {
                    // Just search for locale
                    query += $"AND IS_DEFINED(tags.{nameof(ApplicationRegistration.LocalizedNames)}" +
                        $".{model.Locale}) ";
                }
            }
            if (model?.ApplicationName != null) {
                // If application name provided, also search default name
                query += $"AND tags.{nameof(ApplicationRegistration.ApplicationName)} = " +
                    $"'{model.ApplicationName}' ";
            }
            if (model?.ProductUri != null) {
                // If product uri provided, include it in search
                query += $"AND tags.{nameof(ApplicationRegistration.ProductUri)} = " +
                    $"'{model.ProductUri}' ";
            }
            if (model?.GatewayServerUri != null) {
                // If gateway uri provided, include it in search
                query += $"AND tags.{nameof(ApplicationRegistration.GatewayServerUri)} = " +
                    $"'{model.GatewayServerUri}' ";
            }
            if (model?.DiscoveryProfileUri != null) {
                // If discovery profile uri provided, include it in search
                query += $"AND tags.{nameof(ApplicationRegistration.DiscoveryProfileUri)} = " +
                    $"'{model.DiscoveryProfileUri}' ";
            }
            if (model?.ApplicationUri != null) {
                // If ApplicationUri provided, include it in search
                query += $"AND tags.{nameof(ApplicationRegistration.ApplicationUriLC)} = " +
                    $"'{model.ApplicationUri.ToLowerInvariant()}' ";
            }
            if (model?.State != null) {
                // If searching for state include it in search
                query += $"AND tags.{nameof(ApplicationRegistration.ApplicationState)} = " +
                    $"'{model.State}' ";
            }
            if (model?.ApplicationType == ApplicationType.Client ||
                model?.ApplicationType == ApplicationType.ClientAndServer) {
                // If searching for clients include it in search
                query += $"AND tags.{nameof(ApplicationType.Client)} = true ";
            }
            if (model?.ApplicationType == ApplicationType.Server ||
                model?.ApplicationType == ApplicationType.ClientAndServer) {
                // If searching for servers include it in search
                query += $"AND tags.{nameof(ApplicationType.Server)} = true ";
            }
            if (model?.ApplicationType == ApplicationType.DiscoveryServer) {
                // If searching for servers include it in search
                query += $"AND tags.{nameof(ApplicationType.DiscoveryServer)} = true ";
            }
            if (model?.Capability != null) {
                // If Capabilities provided, filter results
                query += $"AND tags.{JTokenEx.SanitizePropertyName(model.Capability).ToUpperInvariant()} = true ";
            }
            if (model?.SiteOrSupervisorId != null) {
                // If ApplicationUri provided, include it in search
                query += $"AND tags.{nameof(BaseRegistration.SiteOrSupervisorId)} = " +
                    $"'{model.SiteOrSupervisorId}' ";
            }

            var queryResult = await _iothub.QueryDeviceTwinsAsync(query, null, pageSize);
            return new ApplicationInfoListModel {
                ContinuationToken = queryResult.ContinuationToken,
                Items = queryResult.Items
                    .Select(ApplicationRegistration.FromTwin)
                    .Select(s => s.ToServiceModel())
                    .ToList()
            };
        }

        /// <inheritdoc/>
        public async Task<ApplicationInfoListModel> ListApplicationsAsync(
            string continuation, int? pageSize) {
            var query = "SELECT * FROM devices WHERE " +
                $"tags.{nameof(ApplicationRegistration.DeviceType)} = 'Application' " +
                $"AND NOT IS_DEFINED(tags.{nameof(BaseRegistration.NotSeenSince)})";
            var result = await _iothub.QueryDeviceTwinsAsync(query, continuation, pageSize);
            return new ApplicationInfoListModel {
                ContinuationToken = result.ContinuationToken,
                Items = result.Items
                    .Select(ApplicationRegistration.FromTwin)
                    .Select(s => s.ToServiceModel())
                    .ToList()
            };
        }

        /// <inheritdoc/>
        public async Task<ApplicationSiteListModel> ListSitesAsync(
            string continuation, int? pageSize) {
            var tag = nameof(BaseRegistration.SiteOrSupervisorId);
            var query = $"SELECT tags.{tag}, COUNT() FROM devices WHERE " +
                $"tags.{nameof(ApplicationRegistration.DeviceType)} = 'Application' " +
                $"GROUP BY tags.{tag}";
            var result = await _iothub.QueryAsync(query, continuation, pageSize);
            return new ApplicationSiteListModel {
                ContinuationToken = result.ContinuationToken,
                Sites = result.Result
                    .Select(o => o.GetValueOrDefault<string>(tag))
                    .Where(s => !string.IsNullOrEmpty(s))
                    .ToList()
            };
        }

        /// <inheritdoc/>
        public async Task UnregisterApplicationAsync(string applicationId) {
            while (true) {
                try {
                    var registration = await GetApplicationRegistrationAsync(applicationId, false);
                    if (registration == null) {
                        break; // Deleted already on another thread
                    }

                    // Delete application
                    await _iothub.DeleteAsync(applicationId, null, registration.Etag);

                    // Notify all - this will clean up all items that are tied to the application id
                    var application = registration.ToServiceModel();
                    await _broker.NotifyAllAsync(l => l.OnApplicationDeletedAsync(application)); 
                    // TODO:  Add authority id from context
                }
                catch (ResourceOutOfDateException ex) {
                    // Retry create/update
                    _logger.Debug(ex, "Retry unregistering application...");
                    continue;
                }
            }
        }

        /// <inheritdoc/>
        public async Task PurgeDisabledApplicationsAsync(TimeSpan notSeenSince) {
            var absolute = DateTime.UtcNow - notSeenSince;
            var query = "SELECT * FROM devices WHERE " +
                $"tags.{nameof(BaseRegistration.DeviceType)} = 'Application' " +
            //    $"AND tags.{nameof(BaseRegistration.NotSeenSince)} <= '{absolute}' " +
                $"AND IS_DEFINED(tags.{nameof(BaseRegistration.NotSeenSince)}) ";
            string continuation = null;
            do {
                var devices = await _iothub.QueryDeviceTwinsAsync(query, continuation);
                foreach (var twin in devices.Items) {
                    var registration = ApplicationRegistration.FromTwin(twin);
                    if (registration.NotSeenSince == null ||
                        registration.NotSeenSince.Value >= absolute) {
                        // Skip
                        continue;
                    }
                    try {
                        // Delete application
                        await _iothub.DeleteAsync(registration.ApplicationId, null, registration.Etag);

                        // Notify all listeners that the application was deleted
                        var application = registration.ToServiceModel();
                        await _broker.NotifyAllAsync(l => l.OnApplicationDeletedAsync(application)); 
                        // TODO:  Add authority id from context
                    }
                    catch (ResourceOutOfDateException) {
                        continue;  // Resource has changed since query.
                    }
                    catch (Exception ex) {
                        _logger.Error(ex, "Exception purging application {application} - continue", 
                            registration.ApplicationId);
                        continue;
                    }
                }
                continuation = devices.ContinuationToken;
            }
            while (continuation != null);
        }

        /// <inheritdoc/>
        public async Task ProcessDiscoveryEventsAsync(string siteId, string supervisorId,
            DiscoveryResultModel result, IEnumerable<DiscoveryEventModel> events) {
            if (string.IsNullOrEmpty(siteId)) {
                throw new ArgumentNullException(nameof(siteId));
            }
            if (string.IsNullOrEmpty(supervisorId)) {
                throw new ArgumentNullException(nameof(supervisorId));
            }
            if (result == null) {
                throw new ArgumentNullException(nameof(result));
            }

            //
            // Get all applications for this supervisor or the site the application
            // was found in.  There should only be one site in the found application set
            // or none, otherwise, throw.  The OR covers where site of a supervisor was
            // changed after a discovery run (same supervisor that registered, but now
            // different site reported).
            //
            var twins = await _iothub.QueryDeviceTwinsAsync("SELECT * FROM devices WHERE " +
                $"tags.{nameof(BaseRegistration.DeviceType)} = 'Application' AND " +
                $"(tags.{nameof(ApplicationRegistration.SiteId)} = '{siteId}' OR" +
                $" tags.{nameof(BaseRegistration.SupervisorId)} = '{supervisorId}')");
            var existing = twins
                .Select(ApplicationRegistration.FromTwin);
            var found = events
                .Select(ev => ApplicationRegistration.FromServiceModel(ev.Application,
                    false));

            // Create endpoints lookup table per found application id
            var endpoints = events.GroupBy(k => k.Application.ApplicationId).ToDictionary(
                group => group.Key,
                group => group
                    .Select(ev =>
                        new EndpointInfoModel {
                            ApplicationId = group.Key,
                            Registration = ev.Registration
                        })
                    .ToList());
            //
            // Merge found with existing applications. For disabled applications this will
            // take ownership regardless of supervisor, unfound applications are only disabled
            // and existing ones are patched only if they were previously reported by the same
            // supervisor.  New ones are simply added.
            //
            var remove = new HashSet<ApplicationRegistration>(existing,
                ApplicationRegistration.Logical);
            var add = new HashSet<ApplicationRegistration>(found,
                ApplicationRegistration.Logical);
            var unchange = new HashSet<ApplicationRegistration>(existing,
                ApplicationRegistration.Logical);
            var change = new HashSet<ApplicationRegistration>(found,
                ApplicationRegistration.Logical);

            unchange.IntersectWith(add);
            change.IntersectWith(remove);
            remove.ExceptWith(found);
            add.ExceptWith(existing);

            var added = 0;
            var updated = 0;
            var unchanged = 0;
            var removed = 0;

            if (!(result.RegisterOnly ?? false)) {
                // Remove applications
                foreach (var item in remove) {
                    try {
                        // Only touch applications the supervisor owns.
                        if (item.SupervisorId == supervisorId) {
                            if (!(item.IsDisabled ?? false)) {
                                // Disable
                                var application = item.ToServiceModel();
                                if (!(item.IsDisabled ?? false)) {
                                    application.Updated = new RegistryOperationModel {
                                        AuthorityId = null, // TODO Add authority
                                        Time = DateTime.UtcNow
                                    };
                                    application.NotSeenSince = application.Updated.Time;
                                    await _iothub.PatchAsync(ApplicationRegistration.Patch(
                                        item, ApplicationRegistration.FromServiceModel(
                                            application, true)), true);
                                }
                                await _broker.NotifyAllAsync(l => l.OnApplicationDisabledAsync(application));
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
                        _logger.Error(ex, "Exception during application removal.");
                    }
                }
            }

            // Update applications and ...
            foreach (var exists in unchange) {
                try {
                    if (exists.SupervisorId == supervisorId || (exists.IsDisabled ?? false)) {
                        // Get the new one we will patch over the existing one...
                        var patch = change.First(x =>
                            ApplicationRegistration.Logical.Equals(x, exists));
                        if (exists != patch) {

                            var application = patch.ToServiceModel();
                            application.Updated = new RegistryOperationModel {
                                AuthorityId = null, // TODO Add authority
                                Time = DateTime.UtcNow
                            };
                            application.NotSeenSince = null;
                            await _iothub.PatchAsync(ApplicationRegistration.Patch(exists,
                                ApplicationRegistration.FromServiceModel(application, false)), true);

                            if (exists.IsDisabled ?? false) {
                                await _broker.NotifyAllAsync(l => l.OnApplicationEnabledAsync(application));
                            }
                            await _broker.NotifyAllAsync(l => l.OnApplicationUpdatedAsync(application));
                            updated++;
                        }
                        else {
                            unchanged++;
                        }

                        endpoints.TryGetValue(patch.ApplicationId, out var epFound);
                        // TODO: Handle case where we take ownership of all endpoints
                        await _bulk.ProcessDiscoveryEventsAsync(epFound, result, supervisorId,
                            patch.ApplicationId, false);
                    }
                    else {
                        // TODO: Decide whether we merge endpoints...
                        unchanged++;
                    }
                }
                catch (Exception ex) {
                    unchanged++;
                    _logger.Error(ex, "Exception during update.");
                }
            }

            // ... add brand new applications
            foreach (var item in add) {
                try {
                    var application = item.ToServiceModel();
                    application.Created = new RegistryOperationModel {
                        AuthorityId = null, // TODO Add authority
                        Time = DateTime.UtcNow
                    };
                    application.NotSeenSince = null;
                    var twin = ApplicationRegistration.Patch(null, 
                        ApplicationRegistration.FromServiceModel(application, false));
                    await _iothub.CreateAsync(twin, true);

                    // Notify addition!
                    await _broker.NotifyAllAsync(l => l.OnApplicationNewAsync(application));
                    await _broker.NotifyAllAsync(l => l.OnApplicationEnabledAsync(application));

                    // Now - add all new endpoints
                    endpoints.TryGetValue(item.ApplicationId, out var epFound);
                    await _bulk.ProcessDiscoveryEventsAsync(epFound, result, 
                        supervisorId, null, false);
                    added++;
                }
                catch (Exception ex) {
                    unchanged++;
                    _logger.Error(ex, "Exception during discovery addition.");
                }
            }

            var log = added != 0 || removed != 0 || updated != 0;
#if DEBUG
            log = true;
#endif
            if (log) {
                _logger.Information("... processed discovery results from {supervisorId}: " +
                    "{added} applications added, {updated} enabled, {removed} disabled, and " +
                    "{unchanged} unchanged.", supervisorId, added, updated, removed, unchanged);
            }
        }

        /// <summary>
        /// Update application state
        /// </summary>
        /// <param name="applicationId"></param>
        /// <param name="state"></param>
        /// <param name="precondition"></param>
        /// <param name="authorityId"></param>
        /// <returns></returns>
        private async Task<ApplicationInfoModel> UpdateApplicationStateAsync(string applicationId,
            ApplicationState state, Func<ApplicationState?, bool> precondition, string authorityId) {
            if (string.IsNullOrEmpty(applicationId)) {
                throw new ArgumentNullException(nameof(applicationId),
                    "The application id must be provided");
            }
            while (true) {
                var registration = await GetApplicationRegistrationAsync(applicationId);
                if (registration == null) {
                    throw new ResourceNotFoundException(
                        "A record with the specified application id does not exist.");
                }

                var application = registration.ToServiceModel();
                if (registration.IsDisabled ?? false) {
                    throw new ResourceInvalidStateException("The application is disabled.");
                }
                if (precondition != null && !precondition(registration.ApplicationState)) {
                    throw new ResourceInvalidStateException(
                        "The application is not in a valid state for this operation.");
                }

                application.State = state;
                application.Approved = new RegistryOperationModel {
                    AuthorityId = authorityId,
                    Time = DateTime.UtcNow
                };
                try {
                    var result = await _iothub.PatchAsync(ApplicationRegistration.Patch(
                        registration, ApplicationRegistration.FromServiceModel(application)));
                    return ApplicationRegistration.FromTwin(result).ToServiceModel();
                }
                catch (ResourceOutOfDateException) {
                    _logger.Verbose("Retry update application state operation.");
                    continue;
                }
            }
        }

        /// <summary>
        /// Retrieve the application registration
        /// </summary>
        /// <param name="applicationId"></param>
        /// <param name="throwIfNotFound"></param>
        /// <returns></returns>
        private async Task<ApplicationRegistration> GetApplicationRegistrationAsync(
            string applicationId, bool throwIfNotFound = true) {
            if (string.IsNullOrEmpty(applicationId)) {
                throw new ArgumentException(nameof(applicationId));
            }
            // Get existing application and compare to see if we need to patch.
            var twin = await _iothub.GetAsync(applicationId);
            if (twin.Id != applicationId) {
                throw new ArgumentException("Id must be same as application to patch",
                    nameof(applicationId));
            }

            // Convert to application registration
            var registration = BaseRegistration.ToRegistration(twin)
                as ApplicationRegistration;
            if (registration == null && throwIfNotFound) {
                throw new ResourceNotFoundException("Not an application registration");
            }
            return registration;
        }

        private readonly IIoTHubTwinServices _iothub;
        private readonly ILogger _logger;
        private readonly IEndpointBulkProcessor _bulk;
        private readonly IEndpointRegistry2 _endpoints;
        private readonly IApplicationRegistryBroker _broker;
    }
}
