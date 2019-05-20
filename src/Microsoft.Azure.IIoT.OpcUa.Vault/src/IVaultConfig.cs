// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------


namespace Microsoft.Azure.IIoT.OpcUa.Vault {

    /// <summary>
    /// Vault configuration
    /// </summary>
    public interface IVaultConfig {

        /// <summary>
        /// Host the vault is running on
        /// </summary>
        string ServiceHost { get; }

        /// <summary>
        /// Auto approve applications
        /// </summary>
        bool ApplicationsAutoApprove { get; }
    }
}
