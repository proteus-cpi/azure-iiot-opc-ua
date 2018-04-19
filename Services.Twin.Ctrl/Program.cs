﻿// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace Microsoft.Azure.IoTSolutions.OpcTwin.Services.Ctrl {
    using Microsoft.Azure.IoTSolutions.OpcTwin.Services.External;
    using Microsoft.Azure.IoTSolutions.OpcTwin.Services.External.Stack;
    using Microsoft.Azure.IoTSolutions.OpcTwin.Services.External.IoTHub;
    using Microsoft.Azure.IoTSolutions.OpcTwin.Services.Models;
    using Microsoft.Azure.IoTSolutions.OpcTwin.Services.Runtime;
    using Microsoft.Azure.IoTSolutions.OpcTwin.EdgeService.Discovery;
    using Microsoft.Azure.IoTSolutions.OpcTwin.EdgeService.Exporter;
    using Microsoft.Azure.IoTSolutions.Common.Diagnostics;
    using Microsoft.Azure.IoTSolutions.Common.Utils;
    using Microsoft.Azure.IoTSolutions.Common.Http;
    using Microsoft.Azure.Devices.Edge;
    using Microsoft.Azure.Devices.Edge.Hosting;
    using Microsoft.Extensions.Configuration;
    using Newtonsoft.Json;
    using Opc.Ua;
    using Opc.Ua.Client;
    using System;
    using System.Collections.Generic;
    using System.Diagnostics;
    using System.IO;
    using System.Text;
    using System.Threading.Tasks;
    using System.Net;
    using System.Threading;
    using System.Linq;

    /// <summary>
    /// Sample program to run imports
    /// </summary>
    public class Program {

        /// <summary>
        /// Test configuration
        /// </summary>
        private class OpcUaTestConfig : IOpcUaServicesConfig {
            public string IoTHubConnString => Environment.GetEnvironmentVariable("_HUB_CS");
            public bool BypassProxy { get; set; }
        }

        enum Op {
            None,
            TestOpcUaServerClient,
            TestOpcUaDiscoveryService,
            TestOpcUaExportService,
            TestOpcUaServerScanner,
            TestNetworkScanner,
            TestPortScanner,
            MakeEdgeSupervisor,
            ClearEdgeSupervisors,
            ClearRegistry
        }

        /// <summary>
        /// Importer entry point
        /// </summary>
        /// <param name="args">command-line arguments</param>
        public static void Main(string[] args) {
            var op = Op.None;
            var proxy = false;
            var endpoint = new EndpointModel { IsTrusted = true };
            var host = Utils.GetHostName();
            string deviceId = null, moduleId = null;

            var configuration = new ConfigurationBuilder().AddEnvironmentVariables().Build();
            try {
                for (var i = 0; i < args.Length; i++) {
                    switch (args[i]) {
                        case "-s":
                        case "--server":
                            if (op != Op.None) {
                                throw new ArgumentException("Operations are mutually exclusive");
                            }
                            op = Op.TestOpcUaServerClient;
                            i++;
                            if (i < args.Length) {
                                endpoint.Url = args[i];
                            }
                            else {
                                endpoint.Url = "opc.tcp://" + host + ":51210/UA/SampleServer";
                            }
                            break;
                        case "-m":
                        case "--make":
                            if (op != Op.None) {
                                throw new ArgumentException("Operations are mutually exclusive");
                            }
                            op = Op.MakeEdgeSupervisor;
                            i++;
                            if (i < args.Length) {
                                deviceId = args[i];
                                i++;
                                if (i < args.Length) {
                                    moduleId = args[i];
                                    break;
                                }
                            }
                            throw new ArgumentException("Missing arguments to make edge device");
                        case "-e":
                        case "--export":
                            if (op != Op.None) {
                                throw new ArgumentException("Operations are mutually exclusive");
                            }
                            op = Op.TestOpcUaExportService;
                            i++;
                            if (i < args.Length) {
                                endpoint.Url = args[i];
                            }
                            else {
                                endpoint.Url = "opc.tcp://" + host + ":51210/UA/SampleServer";
                            }
                            break;
                        case "-P":
                        case "--proxy":
                            proxy = true;
                            break;
                        case "-c":
                        case "--clear":
                            if (op != Op.None) {
                                throw new ArgumentException("Operations are mutually exclusive");
                            }
                            op = Op.ClearRegistry;
                            break;
                        case "-C":
                        case "--clear-edge":
                            if (op != Op.None) {
                                throw new ArgumentException("Operations are mutually exclusive");
                            }
                            op = Op.ClearEdgeSupervisors;
                            break;
                        case "-p":
                        case "--ports":
                            if (op != Op.None) {
                                throw new ArgumentException("Operations are mutually exclusive");
                            }
                            op = Op.TestPortScanner;
                            i++;
                            if (i < args.Length) {
                                host = args[i];
                            }
                            break;
                        case "-o":
                        case "--opcservers":
                            if (op != Op.None) {
                                throw new ArgumentException("Operations are mutually exclusive");
                            }
                            op = Op.TestOpcUaServerScanner;
                            i++;
                            if (i < args.Length) {
                                host = args[i];
                            }
                            break;
                        case "-n":
                        case "--net":
                            if (op != Op.None) {
                                throw new ArgumentException("Operations are mutually exclusive");
                            }
                            op = Op.TestNetworkScanner;
                            break;
                        case "-d":
                        case "--discover":
                            if (op != Op.None) {
                                throw new ArgumentException("Operations are mutually exclusive");
                            }
                            op = Op.TestOpcUaDiscoveryService;
                            break;
                        case "-?":
                        case "-h":
                        case "--help":
                            throw new ArgumentException("Help");
                        default:
                            throw new ArgumentException($"Unknown {args[i]}");
                    }
                }
                if (op == Op.None) {
                    throw new ArgumentException("Missing operation.");
                }
            }
            catch (Exception e) {
                Console.WriteLine(e.Message);
                Console.WriteLine(
                    @"
Services Client
usage:       Services.Client [options] operation [args]

Options:

    --help
     -?
     -h      Prints out this help.

Target (Mutually exclusive):

     -P
    --proxy
             Use proxy

Operations (Mutually exclusive):
     -n
    --network
             Tests network scanning.
     -p
    --ports
             Tests port scanning.
     -o
    --opcservers
             Tests opc server scanning on single machine.
     -d
    --discover
             Tests discovery stuff.
     -c
    --clear
             Clear device registry content.
     -m
    --make
             Make edge supervisor module.
     -e
    --export
             Tests server model export with passed endpoint url.
     -s
    --server
             Tests server stuff with passed endpoint url.  The server
             is queried or browsed to gather all nodes to import.
"
                    );
                return;
            }

            try {
                Console.WriteLine($"Running {op}...");
                switch(op) {
                    case Op.TestOpcUaServerClient:
                        TestOpcUaServerClient(endpoint, proxy).Wait();
                        break;
                    case Op.TestNetworkScanner:
                        TestNetworkScanner().Wait();
                        break;
                    case Op.TestPortScanner:
                        TestPortScanner(host, false).Wait();
                        break;
                    case Op.TestOpcUaServerScanner:
                        TestPortScanner(host, true).Wait();
                        break;
                    case Op.TestOpcUaDiscoveryService:
                        TestOpcUaDiscoveryService().Wait();
                        break;
                    case Op.TestOpcUaExportService:
                        TestOpcUaModelExportService(endpoint).Wait();
                        break;
                    case Op.MakeEdgeSupervisor:
                        MakeEdgeSupervisor(deviceId, moduleId).Wait();
                        break;
                    case Op.ClearEdgeSupervisors:
                        ClearEdgeSupervisors().Wait();
                        break;
                    case Op.ClearRegistry:
                        ClearRegistry().Wait();
                        break;
                    default:
                        throw new ArgumentException("Unknown.");
                }
            }
            catch (Exception e) {
                Console.WriteLine(e);
            }

            Console.WriteLine("Press key to exit...");
            Console.ReadKey();
        }

        /// <summary>
        /// Make edge supervisor
        /// </summary>
        /// <returns></returns>
        private static async Task MakeEdgeSupervisor(string deviceId, string moduleId) {
            var logger = new ConsoleLogger("test", LogLevel.Debug);
            var config = new OpcUaTestConfig {
                BypassProxy = true
            };
            var registry = new IoTHubServiceHttpClient(new HttpClient(logger),
                config, logger);


            await registry.CreateOrUpdateAsync(new External.Models.DeviceTwinModel {
                Id = deviceId,
                ModuleId = moduleId
            });

            var module = await registry.GetRegistrationAsync(deviceId, moduleId);
            Console.WriteLine(JsonConvert.SerializeObject(module));
            var twin = await registry.GetAsync(deviceId, moduleId);
            Console.WriteLine(JsonConvert.SerializeObject(twin));
            var cs = ConnectionString.Parse(config.IoTHubConnString);
            Console.WriteLine("Connection string:");
            Console.WriteLine($"HostName={cs.HostName};DeviceId={deviceId};" +
                $"ModuleId={moduleId};SharedAccessKey={module.Authentication.PrimaryKey}");
        }

        /// <summary>
        /// Clear registry
        /// </summary>
        /// <returns></returns>
        private static async Task ClearEdgeSupervisors() {
            var logger = new ConsoleLogger("test", LogLevel.Debug);
            var config = new OpcUaTestConfig {
                BypassProxy = true
            };
            var registry = new IoTHubServiceHttpClient(new HttpClient(logger),
                config, logger);

            var supers = await registry.QueryAsync(
                "SELECT * from devices.modules where properties.reported.type = 'supervisor'");
            foreach (var item in supers) {
                foreach (var tag in item.Tags.Keys.ToList()) {
                    item.Tags[tag] = null;
                }
                foreach (var property in item.Properties.Desired.Keys.ToList()) {
                    item.Properties.Desired[property] = null;
                }
                foreach (var property in item.Properties.Reported.Keys.ToList()) {
                    if (!item.Properties.Desired.ContainsKey(property)) {
                        item.Properties.Desired.Add(property, null);
                    }
                }
                await registry.CreateOrUpdateAsync(item);
            }
        }

        /// <summary>
        /// Clear registry
        /// </summary>
        /// <returns></returns>
        private static async Task ClearRegistry() {
            var logger = new ConsoleLogger("test", LogLevel.Debug);
            var config = new OpcUaTestConfig {
                BypassProxy = true
            };
            var registry = new IoTHubServiceHttpClient(new HttpClient(logger),
                config, logger);

            var result = await registry.QueryAsync(
                "SELECT * from devices where IS_DEFINED(tags.DeviceType)");
            foreach (var item in result) {
                await registry.DeleteAsync(item.Id, item.ModuleId);
            }
        }

        /// <summary>
        /// Test port scanning
        /// </summary>
        /// <param name="host"></param>
        /// <returns></returns>
        private static async Task TestPortScanner(string host, bool opc) {
            var logger = new ConsoleLogger("test", LogLevel.Debug);
            var addresses = await Dns.GetHostAddressesAsync(host);
            var cts = new CancellationTokenSource(TimeSpan.FromMinutes(10));
            var watch = Stopwatch.StartNew();
            var results = await PortScanner.ScanAsync(logger,
                PortRange.All.SelectMany(r => r.GetEndpoints(addresses.First())),
                opc ? new OpcUaServerProbe(logger) : null, cts.Token);
            foreach(var result in results) {
                Console.WriteLine($"Found {result} open.");
            }
            Console.WriteLine($"Scan took: {watch.Elapsed}");
        }

        /// <summary>
        /// Test network scanning
        /// </summary>
        /// <returns></returns>
        private static async Task TestNetworkScanner() {
            var logger = new ConsoleLogger("test", LogLevel.Debug);
            var cts = new CancellationTokenSource(TimeSpan.FromMinutes(10));
            var watch = Stopwatch.StartNew();
            var results = await NetworkScanner.ScanAsync(logger,
                NetworkClass.Wired, cts.Token);
            foreach (var result in results) {
                Console.WriteLine($"Found {result.Address}...");
            }
            Console.WriteLine($"Scan took: {watch.Elapsed}");
        }

        /// <summary>
        /// Test discovery
        /// </summary>
        /// <returns></returns>
        private static async Task TestOpcUaDiscoveryService() {
            var logger = new ConsoleLogger("test", LogLevel.Debug);
            var client = new OpcUaClient(logger, new OpcUaTestConfig {
                BypassProxy = true
            });

            var discovery = new OpcUaDiscoveryServices(client, new ConsoleEmitter(),
                new EdgeScheduler(), logger);
            await discovery.UpdateConfigurationAsync(new DiscoveryConfigModel {
                IdleTimeBetweenScans = TimeSpan.FromMilliseconds(1)
            });
            await discovery.SetDiscoveryModeAsync(DiscoveryMode.Scan);
            await Task.Delay(TimeSpan.FromMinutes(10));
            await discovery.SetDiscoveryModeAsync(DiscoveryMode.Off);
        }

        /// <summary>
        /// Test model browse
        /// </summary>
        /// <returns></returns>
        private static async Task TestOpcUaModelExportService(EndpointModel endpoint) {
            var logger = new ConsoleLogger("test", LogLevel.Debug);
            var client = new OpcUaClient(logger, new OpcUaTestConfig {
                BypassProxy = true
            });

            var exporter = new OpcUaExportServices(client, new ConsoleUploader(),
                new ConsoleEmitter(), new EdgeScheduler(), logger) {
                ExportIdleTime = TimeSpan.FromMilliseconds(1)
            };
            var id = await exporter.StartModelExportAsync(endpoint, "application/ua-json");
            await Task.Delay(TimeSpan.FromMinutes(10));
            await exporter.StopModelExportAsync(id);
        }

        /// <summary>
        /// Test client stuff
        /// </summary>
        /// <param name="endpoint"></param>
        /// <param name="useProxy"></param>
        private static async Task TestOpcUaServerClient(EndpointModel endpoint,
            bool useProxy) {
            var logger = new ConsoleLogger("test", LogLevel.Debug);
            var client = new OpcUaClient(logger, new OpcUaTestConfig {
                BypassProxy = !useProxy
            });
            await client.ExecuteServiceAsync(endpoint, async session => {

                Console.WriteLine("Browse the OPC UA server namespace.");
                var w = Stopwatch.StartNew();
                var stack = new Stack<Tuple<string, ReferenceDescription>>();
                session.Browse(null, null, ObjectIds.ObjectsFolder,
                    0u, BrowseDirection.Forward, ReferenceTypeIds.HierarchicalReferences,
                    true, (uint)NodeClass.Variable | (uint)NodeClass.Object | (uint)NodeClass.Method,
                    out var continuationPoint, out var references);
                Console.WriteLine(" DisplayName, BrowseName, NodeClass");
                references.Reverse();
                foreach (var rd in references) {
                    stack.Push(Tuple.Create("", rd));
                }
                while (stack.Count > 0) {
                    var browsed = stack.Pop();
                    session.Browse(null, null,
                        ExpandedNodeId.ToNodeId(browsed.Item2.NodeId, session.NamespaceUris),
                        0u, BrowseDirection.Forward, ReferenceTypeIds.HierarchicalReferences,
                        true, (uint)NodeClass.Variable | (uint)NodeClass.Object | (uint)NodeClass.Method,
                        out continuationPoint, out references);
                    references.Reverse();
                    foreach (var rd in references) {
                        stack.Push(Tuple.Create(browsed.Item1 + "   ", rd));
                    }
                    Console.WriteLine($"{browsed.Item1}{(references.Count == 0 ? "-" : "+")} " +
                        $"{browsed.Item2.DisplayName}, {browsed.Item2.BrowseName}, {browsed.Item2.NodeClass}");
                }
                Console.WriteLine($"   ....        took {w.ElapsedMilliseconds} ms...");
                Console.WriteLine("Create a subscription with publishing interval of 1 second.");
                var subscription = new Subscription(session.DefaultSubscription) { PublishingInterval = 1000 };
                Console.WriteLine("Add a list of items (server current time and status) to the subscription.");
                var list = new List<MonitoredItem> {
                    new MonitoredItem(subscription.DefaultItem) {
                        DisplayName = "ServerStatusCurrentTime", StartNodeId = "i=2258",
                    }
                };
                list.ForEach(m => m.Notification += (item, e) => {
                    foreach (var value in item.DequeueValues()) {
                        Console.WriteLine(
                            $"{item.DisplayName}: {value.Value}, {value.SourceTimestamp}, {value.StatusCode}");
                    }
                });
                subscription.AddItems(list);
                Console.WriteLine("Add the subscription to the session.");
                session.AddSubscription(subscription);
                subscription.Create();

                await Task.Delay(60000);
                Console.WriteLine("Delete the subscription from the session.");
                subscription.Delete(false);
                subscription.Dispose();
                return true;
            });
        }

        private class ConsoleEmitter : IEventEmitter {

            public string DeviceId { get; } = "";

            public string ModuleId { get; } = "";

            public Task SendAsync(byte[] data, string contentType) {
                var json = Encoding.UTF8.GetString(data);
                var o = JsonConvert.DeserializeObject(json);
                Console.WriteLine(contentType);
                Console.WriteLine(JsonConvertEx.SerializeObjectPretty(o));
                return Task.CompletedTask;
            }

            public async Task SendAsync(IEnumerable<byte[]> batch, string contentType) {
                foreach (var data in batch) {
                    await SendAsync(data, contentType);
                }
            }

            public Task SendAsync(string propertyId, dynamic value) {
                Console.WriteLine($"{propertyId}={value}");
                return Task.CompletedTask;
            }

            public Task SendAsync(IEnumerable<KeyValuePair<string, dynamic>> properties) {
                foreach (var prop in properties) {
                    Console.WriteLine($"{prop.Key}={prop.Value}");
                }
                return Task.CompletedTask;
            }
        }

        private class ConsoleUploader : IBlobUpload {
            public Task SendAsync(string fileName, string contentType) {
                using (var stream = new FileStream(fileName, FileMode.Open)) {
                    Console.WriteLine(new StringReader(fileName).ReadToEnd());
                }
                return Task.CompletedTask;
            }
        }
    }
}