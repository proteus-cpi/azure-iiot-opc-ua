// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace Microsoft.Azure.IIoT.OpcUa.Registry {
    using Microsoft.Azure.IIoT.OpcUa.Registry.Services;
    using Autofac;

    /// <summary>
    /// Injected registry services
    /// </summary>
    public sealed class RegistryModule : Module {

        /// <summary>
        /// Load the module
        /// </summary>
        /// <param name="builder"></param>
        protected override void Load(ContainerBuilder builder) {

            // Services
            builder.RegisterType<EndpointRegistry>()
                .AsImplementedInterfaces().SingleInstance();
            builder.RegisterType<ApplicationRegistry>()
                .AsImplementedInterfaces().SingleInstance();
            builder.RegisterType<SupervisorRegistry>()
                .AsImplementedInterfaces().SingleInstance();
            builder.RegisterType<DiscoveryProcessor>()
                .AsImplementedInterfaces().SingleInstance();

            base.Load(builder);
        }
    }
}
