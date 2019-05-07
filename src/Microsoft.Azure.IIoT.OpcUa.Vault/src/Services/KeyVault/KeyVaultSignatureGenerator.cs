// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace Microsoft.Azure.IIoT.OpcUa.Vault.KeyVault {
    using System;
    using System.Security.Cryptography;
    using System.Security.Cryptography.X509Certificates;

    /// <summary>
    /// The X509 signature generator to sign a digest with a KeyVault key.
    /// </summary>
    public class KeyVaultSignatureGenerator : X509SignatureGenerator {
        private readonly X509Certificate2 _issuerCert;
        private readonly KeyVaultServiceClient _keyVaultServiceClient;
        private readonly string _signingKey;

        /// <summary>
        /// Create the KeyVault signature generator.
        /// </summary>
        /// <param name="keyVaultServiceClient">The KeyVault service client to use</param>
        /// <param name="signingKey">The KeyVault signing key</param>
        /// <param name="issuerCertificate">The issuer certificate used for signing</param>
        public KeyVaultSignatureGenerator(
            KeyVaultServiceClient keyVaultServiceClient,
            string signingKey,
            X509Certificate2 issuerCertificate) {
            _issuerCert = issuerCertificate;
            _keyVaultServiceClient = keyVaultServiceClient;
            _signingKey = signingKey;
        }

        /// <summary>
        /// Callback to sign a digest with KeyVault key.
        /// </summary>
        /// <param name="data"></param>
        /// <param name="hashAlgorithm"></param>
        /// <returns></returns>
        public override byte[] SignData(byte[] data, HashAlgorithmName hashAlgorithm) {
            HashAlgorithm hash;
            if (hashAlgorithm == HashAlgorithmName.SHA256) {
                hash = SHA256.Create();
            }
            else if (hashAlgorithm == HashAlgorithmName.SHA384) {
                hash = SHA384.Create();
            }
            else if (hashAlgorithm == HashAlgorithmName.SHA512) {
                hash = SHA512.Create();
            }
            else {
                throw new ArgumentOutOfRangeException(nameof(hashAlgorithm), "The hash algorithm " + hashAlgorithm.Name + " is not supported.");
            }
            var digest = hash.ComputeHash(data);
            var resultKeyVaultPkcs = _keyVaultServiceClient.SignDigestAsync(_signingKey, digest, hashAlgorithm, RSASignaturePadding.Pkcs1).GetAwaiter().GetResult();
#if TESTANDVERIFYTHEKEYVAULTSIGNER
                // for test and dev only, verify the KeyVault signer acts identical to the internal signer
                if (_issuerCert.HasPrivateKey)
                {
                    var resultKeyVaultPss = _keyVaultServiceClient.SignDigestAsync(_signingKey, digest, hashAlgorithm, RSASignaturePadding.Pss).GetAwaiter().GetResult();
                    var resultLocalPkcs = _issuerCert.GetRSAPrivateKey().SignData(data, hashAlgorithm, RSASignaturePadding.Pkcs1);
                    var resultLocalPss = _issuerCert.GetRSAPrivateKey().SignData(data, hashAlgorithm, RSASignaturePadding.Pss);
                    for (int i = 0; i < resultKeyVaultPkcs.Length; i++)
                    {
                        if (resultKeyVaultPkcs[i] != resultLocalPkcs[i])
                        {
                            Debug.WriteLine("{0} != {1}", resultKeyVaultPkcs[i], resultLocalPkcs[i]);
                        }
                    }
                    for (int i = 0; i < resultKeyVaultPss.Length; i++)
                    {
                        if (resultKeyVaultPss[i] != resultLocalPss[i])
                        {
                            Debug.WriteLine("{0} != {1}", resultKeyVaultPss[i], resultLocalPss[i]);
                        }
                    }
                }
#endif
            return resultKeyVaultPkcs;
        }

        /// <inheritdoc/>
        protected override PublicKey BuildPublicKey() {
            return _issuerCert.PublicKey;
        }

        /// <summary>
        /// Build public key
        /// </summary>
        /// <param name="rsa"></param>
        /// <returns></returns>
        internal static PublicKey BuildPublicKey(RSA rsa) {
            if (rsa == null) {
                throw new ArgumentNullException(nameof(rsa));
            }
            // function is never called
            return null;
        }

        /// <inheritdoc/>
        public override byte[] GetSignatureAlgorithmIdentifier(HashAlgorithmName hashAlgorithm) {
            byte[] oidSequence;

            if (hashAlgorithm == HashAlgorithmName.SHA256) {
                //const string RsaPkcs1Sha256 = "1.2.840.113549.1.1.11";
                oidSequence = new byte[] { 48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 11, 5, 0 };
            }
            else if (hashAlgorithm == HashAlgorithmName.SHA384) {
                //const string RsaPkcs1Sha384 = "1.2.840.113549.1.1.12";
                oidSequence = new byte[] { 48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 12, 5, 0 };
            }
            else if (hashAlgorithm == HashAlgorithmName.SHA512) {
                //const string RsaPkcs1Sha512 = "1.2.840.113549.1.1.13";
                oidSequence = new byte[] { 48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 13, 5, 0 };
            }
            else {
                throw new ArgumentOutOfRangeException(nameof(hashAlgorithm), "The hash algorithm " + hashAlgorithm.Name + " is not supported.");
            }
            return oidSequence;
        }
    }
}
