﻿// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace Microsoft.Azure.IIoT.OpcUa.Vault {
    using Microsoft.Azure.IIoT.Crypto.Models;
    using System;
    using System.Collections.Generic;
    using System.Security.Cryptography;
    using System.Security.Cryptography.X509Certificates;
    using System.Threading.Tasks;

    /// <summary>
    /// Application Certificate factory
    /// </summary>
    public interface IApplicationCertificateFactory {

        /// <summary>
        /// Creates a signed certificate
        /// </summary>
        /// <param name="issuerCAKeyCert"></param>
        /// <param name="publicKey"></param>
        /// <param name="subjectName"></param>
        /// <param name="applicationUri"></param>
        /// <param name="applicationName"></param>
        /// <param name="domainNames"></param>
        /// <param name="keySize"></param>
        /// <param name="notBefore"></param>
        /// <param name="notAfter"></param>
        /// <param name="hashSizeInBits"></param>
        /// <param name="extensionUrl"></param>
        /// <returns></returns>
        Task<X509Certificate2> CreateSignedCertificateAsync(X509CertificateKeyIdPair issuerCAKeyCert,
            RSA publicKey, string subjectName, string applicationUri, string applicationName,
            IList<string> domainNames, ushort keySize, DateTime notBefore, DateTime notAfter,
            ushort hashSizeInBits, string extensionUrl = null);

    }
}