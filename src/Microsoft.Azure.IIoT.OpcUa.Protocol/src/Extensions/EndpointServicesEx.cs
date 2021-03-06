// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace Microsoft.Azure.IIoT.OpcUa.Protocol {
    using Microsoft.Azure.IIoT.OpcUa.Registry.Models;
    using System.Threading.Tasks;
    using System;
    using Opc.Ua.Client;
    using System.Threading;

    /// <summary>
    /// Endpoint services extensions
    /// </summary>
    public static class EndpointServicesEx {

        /// <summary>
        /// Overload that runs in the foreground, does not continue on exception
        /// but allows specifying timeout.
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="client"></param>
        /// <param name="elevation"></param>
        /// <param name="timeout"></param>
        /// <param name="endpoint"></param>
        /// <param name="service"></param>
        /// <returns></returns>
        public static Task<T> ExecuteServiceAsync<T>(this IEndpointServices client,
            EndpointModel endpoint, CredentialModel elevation, TimeSpan timeout,
            Func<Session, Task<T>> service) {
            return client.ExecuteServiceAsync(endpoint, elevation, 0, service,
                timeout, CancellationToken.None, _ => true);
        }

        /// <summary>
        /// Overload that runs in the foreground, does not continue on exception
        /// times out after 30 seconds.
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="client"></param>
        /// <param name="elevation"></param>
        /// <param name="endpoint"></param>
        /// <param name="service"></param>
        /// <returns></returns>
        public static Task<T> ExecuteServiceAsync<T>(this IEndpointServices client,
            EndpointModel endpoint, CredentialModel elevation, Func<Session, Task<T>> service) {
            return client.ExecuteServiceAsync(endpoint, elevation, TimeSpan.FromSeconds(30),
                service);
        }

        /// <summary>
        /// Overload that does not continue on exception and can only be cancelled.
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="client"></param>
        /// <param name="elevation"></param>
        /// <param name="priority"></param>
        /// <param name="ct"></param>
        /// <param name="endpoint"></param>
        /// <param name="service"></param>
        /// <returns></returns>
        public static Task<T> ExecuteServiceAsync<T>(this IEndpointServices client,
            EndpointModel endpoint, CredentialModel elevation, int priority,
            CancellationToken ct, Func<Session, Task<T>> service) {
            return client.ExecuteServiceAsync(endpoint, elevation, priority, ct, service,
                _ => true);
        }

        /// <summary>
        /// Overload which can only be cancelled.
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="client"></param>
        /// <param name="elevation"></param>
        /// <param name="priority"></param>
        /// <param name="ct"></param>
        /// <param name="endpoint"></param>
        /// <param name="service"></param>
        /// <param name="handler"></param>
        /// <returns></returns>
        public static Task<T> ExecuteServiceAsync<T>(this IEndpointServices client,
            EndpointModel endpoint, CredentialModel elevation, int priority,
            CancellationToken ct, Func<Session, Task<T>> service,
            Func<Exception, bool> handler) {
            return client.ExecuteServiceAsync(endpoint, elevation, priority, service,
                null, ct, handler);
        }
    }
}
