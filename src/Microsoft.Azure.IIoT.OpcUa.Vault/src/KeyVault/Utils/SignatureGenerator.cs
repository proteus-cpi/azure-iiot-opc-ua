// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace Microsoft.Azure.IIoT.OpcUa.Vault.KeyVault {
    using System;
    using System.Security.Cryptography;
    using System.Security.Cryptography.X509Certificates;

    /// <summary>
    /// The X509 signature generator to sign a digest using 
    /// <see cref="IDigestSigner"/>
    /// </summary>
    internal sealed class SignatureGenerator : X509SignatureGenerator {

        /// <summary>
        /// Create the digest signer signature generator.
        /// </summary>
        /// <param name="signer">Digest signer to use</param>
        /// <param name="signingKey">The signing key</param>
        /// <param name="issuerCertificate">The issuer 
        /// certificate used for signing</param>
        public SignatureGenerator(IDigestSigner signer, string signingKey, 
            X509Certificate2 issuerCertificate) {
            _issuerCert = issuerCertificate;
            _signer = signer;
            _signingKey = signingKey;
        }

        /// <inheritdoc/>
        public override byte[] SignData(byte[] data, HashAlgorithmName hashAlgorithm) {
            var hash = CreateHashAlgorithm(hashAlgorithm);
            var digest = hash.ComputeHash(data);
            var resultKeyVaultPkcs = _signer.SignDigestAsync(
                _signingKey, digest, hashAlgorithm, RSASignaturePadding.Pkcs1)
                .GetAwaiter()
                .GetResult();
#if DEBUG
            //
            // for test and dev only, verify the KeyVault signer acts identical
            // to the internal signer
            //
            if (_issuerCert.HasPrivateKey) {
                var resultKeyVaultPss = _signer.SignDigestAsync(
                    _signingKey, digest, hashAlgorithm, RSASignaturePadding.Pss)
                    .GetAwaiter()
                    .GetResult();
                var resultLocalPkcs = _issuerCert.GetRSAPrivateKey().SignData(
                        data, hashAlgorithm, RSASignaturePadding.Pkcs1);
                var resultLocalPss = _issuerCert.GetRSAPrivateKey().SignData(
                    data, hashAlgorithm, RSASignaturePadding.Pss);
                for (var i = 0; i < resultKeyVaultPkcs.Length; i++) {
                    if (resultKeyVaultPkcs[i] != resultLocalPkcs[i]) {
                        System.Diagnostics.Debug.WriteLine("{0} != {1}",
                            resultKeyVaultPkcs[i], resultLocalPkcs[i]);
                    }
                }
                for (var i = 0; i < resultKeyVaultPss.Length; i++) {
                    if (resultKeyVaultPss[i] != resultLocalPss[i]) {
                        System.Diagnostics.Debug.WriteLine("{0} != {1}",
                            resultKeyVaultPss[i], resultLocalPss[i]);
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

        /// <inheritdoc/>
        public override byte[] GetSignatureAlgorithmIdentifier(HashAlgorithmName hashAlgorithm) {
            if (hashAlgorithm == HashAlgorithmName.SHA256) {
                // const string RsaPkcs1Sha256 = "1.2.840.113549.1.1.11";
                return new byte[] {
                    48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 11, 5, 0
                };
            }
            if (hashAlgorithm == HashAlgorithmName.SHA384) {
                // const string RsaPkcs1Sha384 = "1.2.840.113549.1.1.12";
                return new byte[] {
                    48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 12, 5, 0
                };
            }
            if (hashAlgorithm == HashAlgorithmName.SHA512) {
                // const string RsaPkcs1Sha512 = "1.2.840.113549.1.1.13";
                return new byte[] {
                    48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 13, 5, 0
                };
            }
            throw new ArgumentOutOfRangeException(nameof(hashAlgorithm),
                $"The hash algorithm {hashAlgorithm.Name} is not supported.");
        }

        /// <summary>
        /// Create hash algorithm implementation
        /// </summary>
        /// <param name="hashAlgorithm"></param>
        /// <returns></returns>
        private static HashAlgorithm CreateHashAlgorithm(HashAlgorithmName hashAlgorithm) {
            if (hashAlgorithm == HashAlgorithmName.SHA256) {
                return SHA256.Create();
            }
            if (hashAlgorithm == HashAlgorithmName.SHA384) {
                return SHA384.Create();
            }
            if (hashAlgorithm == HashAlgorithmName.SHA512) {
                return SHA512.Create();
            }
            throw new ArgumentOutOfRangeException(nameof(hashAlgorithm),
                $"The hash algorithm {hashAlgorithm.Name} is not supported.");
        }


        private readonly X509Certificate2 _issuerCert;
        private readonly IDigestSigner _signer;
        private readonly string _signingKey;
    }
}
