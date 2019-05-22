// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace Microsoft.Azure.IIoT.OpcUa.Registry.Default {
    using System;
    using System.Linq;
    using System.Threading.Tasks;
    using System.Collections.Concurrent;

    /// <summary>
    /// Simple in proc registry event broker
    /// </summary>
    public sealed class DefaultEventBroker : IApplicationRegistryBroker,
        IApplicationRegistryEvents, IEndpointRegistryBroker, IEndpointRegistryEvents {

        /// <summary>
        /// Create broker
        /// </summary>
        public DefaultEventBroker() {
            _endpoints = new ConcurrentDictionary<string, IEndpointRegistryListener>();
            _applications = new ConcurrentDictionary<string, IApplicationRegistryListener>();
        }

        /// <inheritdoc/>
        public Action Register(IEndpointRegistryListener listener) {
            var token = Guid.NewGuid().ToString();
            _endpoints.TryAdd(token, listener);
            return () => _endpoints.TryRemove(token, out var _);
        }

        /// <inheritdoc/>
        public Action Register(IApplicationRegistryListener listener) {
            var token = Guid.NewGuid().ToString();
            _applications.TryAdd(token, listener);
            return () => _applications.TryRemove(token, out var _);
        }

        /// <inheritdoc/>
        public Task NotifyAllAsync(Func<IEndpointRegistryListener, Task> evt) {
            return Task
                .WhenAll(_endpoints.Select(l => evt(l.Value)).ToArray())
                .ContinueWith(t => Task.CompletedTask);
        }

        /// <inheritdoc/>
        public Task NotifyAllAsync(Func<IApplicationRegistryListener, Task> evt) {
            return Task
                .WhenAll(_applications.Select(l => evt(l.Value)).ToArray())
                .ContinueWith(t => Task.CompletedTask);
        }

        private readonly ConcurrentDictionary<string, IEndpointRegistryListener> _endpoints;
        private readonly ConcurrentDictionary<string, IApplicationRegistryListener> _applications;
    }
}
