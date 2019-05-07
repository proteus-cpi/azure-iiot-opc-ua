// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------


using Microsoft.Azure.IIoT.OpcUa.Vault.CosmosDB.Models;
using Microsoft.Azure.IIoT.OpcUa.Vault.Models;
using Newtonsoft.Json;
using Opc.Ua;
using Opc.Ua.Gds;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Xunit;

namespace Microsoft.Azure.IIoT.OpcUa.Vault.Tests {
    public class ApplicationTestData {
        public ApplicationTestData() {
            Initialize();
        }

        private void Initialize() {
            ApplicationRecord = new ApplicationRecordDataType();
            CertificateGroupId = null;
            CertificateTypeId = null;
            CertificateRequestId = null;
            DomainNames = new StringCollection();
            Subject = null;
            PrivateKeyFormat = "PFX";
            PrivateKeyPassword = "";
            Certificate = null;
            PrivateKey = null;
            IssuerCertificates = null;
        }

        public ApplicationRecordModel Model { get; set; }
        public ApplicationRecordDataType ApplicationRecord { get; set; }
        public NodeId CertificateGroupId { get; set; }
        public NodeId CertificateTypeId { get; set; }
        public NodeId CertificateRequestId { get; set; }
        public StringCollection DomainNames { get; set; }
        public string Subject { get; set; }
        public string PrivateKeyFormat { get; set; }
        public string PrivateKeyPassword { get; set; }
        public byte[] Certificate { get; set; }
        public byte[] PrivateKey { get; set; }
        public byte[][] IssuerCertificates { get; set; }
        public IList<string> RequestIds { get; set; }

        /// <summary>
        /// Convert the Server Capability array representation to a comma separated string.
        /// </summary>
        public static string ServerCapabilities(string[] serverCapabilities) {
            var capabilities = new StringBuilder();
            if (serverCapabilities != null) {
                foreach (var capability in serverCapabilities) {
                    if (string.IsNullOrEmpty(capability)) {
                        continue;
                    }

                    if (capabilities.Length > 0) {
                        capabilities.Append(',');
                    }
                    capabilities.Append(capability);
                }
            }
            return capabilities.ToString();
        }

        /// <summary>
        /// Helper to assert the application model data which should remain equal.
        /// </summary>
        /// <param name="expected">The expected Application model data</param>
        /// <param name="actual">The actualy Application model data</param>
        public static void AssertEqualApplicationModelData(ApplicationRecordModel expected, ApplicationRecordModel actual) {
            Assert.Equal(expected.ApplicationName, actual.ApplicationName);
            Assert.Equal(expected.ApplicationType, actual.ApplicationType);
            Assert.Equal(expected.ApplicationUri, actual.ApplicationUri);
            Assert.Equal(expected.DiscoveryProfileUri, actual.DiscoveryProfileUri);
            Assert.Equal(expected.ProductUri, actual.ProductUri);
            Assert.Equal(ServerCapabilities(expected), ServerCapabilities(actual));
            Assert.Equal(JsonConvert.SerializeObject(expected.ApplicationNames), JsonConvert.SerializeObject(actual.ApplicationNames));
            Assert.Equal(JsonConvert.SerializeObject(expected.DiscoveryUrls), JsonConvert.SerializeObject(actual.DiscoveryUrls));
        }

        /// <summary>
        /// Normalize and validate the server capabilites.
        /// </summary>
        /// <param name="application">The application with server capabilities.</param>
        /// <returns></returns>
        public static string ServerCapabilities(ApplicationRecordModel application) {
            if (application.ApplicationType != Registry.Models.ApplicationType.Client) {
                if (string.IsNullOrEmpty(application.ServerCapabilities)) {
                    throw new ArgumentException("At least one Server Capability must be provided.", nameof(application.ServerCapabilities));
                }
            }

            // TODO validate against specified capabilites.

            var capabilities = new StringBuilder();
            if (application.ServerCapabilities != null) {
                var sortedCaps = application.ServerCapabilities.Split(",").ToList();
                sortedCaps.Sort();
                foreach (var capability in sortedCaps) {
                    if (string.IsNullOrEmpty(capability)) {
                        continue;
                    }

                    if (capabilities.Length > 0) {
                        capabilities.Append(',');
                    }

                    capabilities.Append(capability);
                }
            }

            return capabilities.ToString();
        }

        public static ApplicationRecordModel ApplicationDeepCopy(ApplicationRecordModel app) {
            // serialize/deserialize to avoid using MemberwiseClone
            return (ApplicationRecordModel)JsonConvert.DeserializeObject(JsonConvert.SerializeObject(app), typeof(ApplicationRecordModel));
        }

    }

}
