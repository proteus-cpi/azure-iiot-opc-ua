// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace Microsoft.Azure.IIoT.OpcUa.Registry {
    using Microsoft.Azure.IIoT.OpcUa.Registry.Models;
    using Microsoft.Azure.IIoT.Utils;
    using System.Collections.Generic;
    using System.Linq;
    using System.Threading.Tasks;

    /// <summary>
    /// Registry services extensions
    /// </summary>
    public static class RegistryServicesEx {

        /// <summary>
        /// Find endpoints using query
        /// </summary>
        /// <param name="service"></param>
        /// <param name="query"></param>
        /// <param name="onlyServerState"></param>
        /// <returns></returns>
        public static async Task<List<EndpointInfoModel>> QueryAllEndpointsAsync(
            this IEndpointRegistry service, EndpointRegistrationQueryModel query,
            bool onlyServerState = false) {
            var registrations = new List<EndpointInfoModel>();
            var result = await service.QueryEndpointsAsync(query, onlyServerState);
            registrations.AddRange(result.Items);
            while (result.ContinuationToken != null) {
                result = await service.ListEndpointsAsync(result.ContinuationToken,
                    onlyServerState);
                registrations.AddRange(result.Items);
            }
            return registrations;
        }

        /// <summary>
        /// List all endpoints
        /// </summary>
        /// <param name="service"></param>
        /// <param name="onlyServerState"></param>
        /// <returns></returns>
        public static async Task<List<EndpointInfoModel>> ListAllEndpointsAsync(
            this IEndpointRegistry service, bool onlyServerState = false) {
            var registrations = new List<EndpointInfoModel>();
            var result = await service.ListEndpointsAsync(null, onlyServerState);
            registrations.AddRange(result.Items);
            while (result.ContinuationToken != null) {
                result = await service.ListEndpointsAsync(result.ContinuationToken,
                    onlyServerState);
                registrations.AddRange(result.Items);
            }
            return registrations;
        }

        /// <summary>
        /// Find applications
        /// </summary>
        /// <param name="service"></param>
        /// <param name="query"></param>
        /// <returns></returns>
        public static async Task<List<ApplicationInfoModel>> QueryAllApplicationsAsync(
            this IApplicationRegistry service, ApplicationRegistrationQueryModel query) {
            var registrations = new List<ApplicationInfoModel>();
            var result = await service.QueryApplicationsAsync(query);
            registrations.AddRange(result.Items);
            while (result.ContinuationToken != null) {
                result = await service.ListApplicationsAsync(result.ContinuationToken);
                registrations.AddRange(result.Items);
            }
            return registrations;
        }

        /// <summary>
        /// List all applications
        /// </summary>
        /// <param name="service"></param>
        /// <returns></returns>
        public static async Task<List<ApplicationInfoModel>> ListAllApplicationsAsync(
            this IApplicationRegistry service) {
            var registrations = new List<ApplicationInfoModel>();
            var result = await service.ListApplicationsAsync(null);
            registrations.AddRange(result.Items);
            while (result.ContinuationToken != null) {
                result = await service.ListApplicationsAsync(result.ContinuationToken);
                registrations.AddRange(result.Items);
            }
            return registrations;
        }

        /// <summary>
        /// List all application registrations
        /// </summary>
        /// <param name="service"></param>
        /// <returns></returns>
        public static async Task<List<ApplicationRegistrationModel>> ListAllRegistrationsAsync(
            this IApplicationRegistry service) {
            var registrations = new List<ApplicationRegistrationModel>();
            var infos = await service.ListAllApplicationsAsync();
            foreach (var info in infos) {
                var registration = await service.GetApplicationAsync(info.ApplicationId);
                registrations.Add(registration);
            }
            return registrations;
        }

        /// <summary>
        /// Unregister all applications and endpoints
        /// </summary>
        /// <param name="service"></param>
        /// <returns></returns>
        public static async Task UnregisterAllApplicationsAsync(
            this IApplicationRegistry service) {
            var apps = await service.ListAllApplicationsAsync();
            foreach (var app in apps) {
                await Try.Async(() => service.UnregisterApplicationAsync(
                    app.ApplicationId));
            }
        }

        /// <summary>
        /// List all sites
        /// </summary>
        /// <param name="service"></param>
        /// <returns></returns>
        public static async Task<List<string>> ListAllSitesAsync(
            this IApplicationRegistry service) {
            var sites = new List<string>();
            var result = await service.ListSitesAsync(null);
            sites.AddRange(result.Sites);
            while (result.ContinuationToken != null) {
                result = await service.ListSitesAsync(result.ContinuationToken);
                sites.AddRange(result.Sites);
            }
            return sites;
        }

        /// <summary>
        /// List all supervisors
        /// </summary>
        /// <param name="service"></param>
        /// <param name="onlyServerState"></param>
        /// <returns></returns>
        public static async Task<List<SupervisorModel>> ListAllSupervisorsAsync(
            this ISupervisorRegistry service, bool onlyServerState = false) {
            var supervisors = new List<SupervisorModel>();
            var result = await service.ListSupervisorsAsync(null, onlyServerState);
            supervisors.AddRange(result.Items);
            while (result.ContinuationToken != null) {
                result = await service.ListSupervisorsAsync(result.ContinuationToken,
                    onlyServerState);
                supervisors.AddRange(result.Items);
            }
            return supervisors;
        }

        /// <summary>
        /// Returns all supervisor ids from the registry
        /// </summary>
        /// <param name="service"></param>
        /// <param name="onlyServerState"></param>
        /// <returns></returns>
        public static async Task<List<string>> ListAllSupervisorIdsAsync(
            this ISupervisorRegistry service, bool onlyServerState = false) {
            var supervisors = new List<string>();
            var result = await service.ListSupervisorsAsync(null, onlyServerState);
            supervisors.AddRange(result.Items.Select(s => s.Id));
            while (result.ContinuationToken != null) {
                result = await service.ListSupervisorsAsync(result.ContinuationToken,
                    onlyServerState);
                supervisors.AddRange(result.Items.Select(s => s.Id));
            }
            return supervisors;
        }
    }
}
