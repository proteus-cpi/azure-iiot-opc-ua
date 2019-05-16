// ------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//  Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
// ------------------------------------------------------------

namespace Microsoft.Azure.IIoT.OpcUa.Vault.KeyVault {
    using System;
    using System.Collections.Generic;
    using System.Net;
    using System.Security.Cryptography;
    using System.Text;

    /// <summary>
    /// Cert utils
    /// </summary>
    public static class CertUtils {

        /// <summary>
        /// Parses a distingushed name. - from Opc stack.
        /// </summary>
        public static List<string> ParseDistinguishedName(string name) {
            var fields = new List<string>();

            if (string.IsNullOrEmpty(name)) {
                return fields;
            }

            // determine the delimiter used.
            var delimiter = ',';
            var found = false;
            var quoted = false;

            for (var index = name.Length - 1; index >= 0; index--) {
                var ch = name[index];

                if (ch == '"') {
                    quoted = !quoted;
                    continue;
                }

                if (!quoted && ch == '=') {
                    index--;
                    while (index >= 0 && char.IsWhiteSpace(name[index])) {
                        index--;
                    }
                    while (index >= 0 && (char.IsLetterOrDigit(name[index]) || name[index] == '.')) {
                        index--;
                    }
                    while (index >= 0 && char.IsWhiteSpace(name[index])) {
                        index--;
                    }
                    if (index >= 0) {
                        delimiter = name[index];
                    }
                    break;
                }
            }

            var buffer = new StringBuilder();

            string key = null;
            string value = null;
            found = false;

            for (var index = 0; index < name.Length; index++) {
                while (index < name.Length && char.IsWhiteSpace(name[index])) {
                    index++;
                }

                if (index >= name.Length) {
                    break;
                }

                var ch = name[index];

                if (found) {
                    var end = delimiter;

                    if (index < name.Length && name[index] == '"') {
                        index++;
                        end = '"';
                    }

                    while (index < name.Length) {
                        ch = name[index];

                        if (ch == end) {
                            while (index < name.Length && name[index] != delimiter) {
                                index++;
                            }

                            break;
                        }

                        buffer.Append(ch);
                        index++;
                    }

                    value = buffer.ToString().TrimEnd();
                    found = false;

                    buffer.Length = 0;
                    buffer.Append(key);
                    buffer.Append('=');

                    if (value.IndexOfAny(new char[] { '/', ',', '=' }) != -1) {
                        if (value.Length > 0 && value[0] != '"') {
                            buffer.Append('"');
                        }

                        buffer.Append(value);

                        if (value.Length > 0 && value[value.Length - 1] != '"') {
                            buffer.Append('"');
                        }
                    }
                    else {
                        buffer.Append(value);
                    }

                    fields.Add(buffer.ToString());
                    buffer.Length = 0;
                }

                else {
                    while (index < name.Length) {
                        ch = name[index];

                        if (ch == '=') {
                            break;
                        }

                        buffer.Append(ch);
                        index++;
                    }

                    key = buffer.ToString().TrimEnd().ToUpperInvariant();
                    buffer.Length = 0;
                    found = true;
                }
            }
            return fields;
        }


        /// <summary>
        /// Compares two distinguished names.
        /// </summary>
        public static bool CompareDistinguishedName(string name1, string name2) {
            // check for simple equality.
            if (string.Compare(name1, name2, StringComparison.OrdinalIgnoreCase) == 0) {
                return true;
            }

            // parse the names.
            var fields1 = ParseDistinguishedName(name1);
            var fields2 = ParseDistinguishedName(name2);

            // can't be equal if the number of fields is different.
            if (fields1.Count != fields2.Count) {
                return false;
            }

            // sort to ensure similar entries are compared
            fields1.Sort(StringComparer.OrdinalIgnoreCase);
            fields2.Sort(StringComparer.OrdinalIgnoreCase);

            // compare each.
            for (var index = 0; index < fields1.Count; index++) {
                if (string.Compare(fields1[index], fields2[index], StringComparison.OrdinalIgnoreCase) != 0) {
                    return false;
                }
            }

            return true;
        }

        /// <summary>
        /// Replaces the cert subject name DC=localhost with the current host name.
        /// </summary>
        public static string ReplaceDCLocalhost(string subjectName, string hostname = null) {
            // ignore nulls.
            if (string.IsNullOrEmpty(subjectName)) {
                return subjectName;
            }

            // IPv6 address needs a surrounding [] 
            if (!string.IsNullOrEmpty(hostname) && hostname.Contains(':')) {
                hostname = "[" + hostname + "]";
            }

            // check if the string DC=localhost is specified.
            var index = subjectName.IndexOf("DC=localhost", StringComparison.OrdinalIgnoreCase);

            if (index == -1) {
                return subjectName;
            }

            // construct new uri.
            var buffer = new StringBuilder();

            buffer.Append(subjectName.Substring(0, index + 3));
            buffer.Append(hostname ?? Dns.GetHostName());
            buffer.Append(subjectName.Substring(index + "DC=localhost".Length));

            return buffer.ToString();
        }

#if UNUSED
        public static string GetRSAHashAlgorithm(uint hashSizeInBits) {
            if (hashSizeInBits <= 160) {
                return "SHA1WITHRSA";
            }

            if (hashSizeInBits <= 224) {
                return "SHA224WITHRSA";
            }
            else if (hashSizeInBits <= 256) {
                return "SHA256WITHRSA";
            }
            else if (hashSizeInBits <= 384) {
                return "SHA384WITHRSA";
            }
            else {
                return "SHA512WITHRSA";
            }
        }
#endif
        /// <summary>
        /// Get name of algorithm based on bits
        /// </summary>
        /// <param name="hashSizeInBits"></param>
        /// <returns></returns>
        public static HashAlgorithmName GetRSAHashAlgorithmName(uint hashSizeInBits) {
            if (hashSizeInBits <= 160) {
                return HashAlgorithmName.SHA1;
            }
            if (hashSizeInBits <= 256) {
                return HashAlgorithmName.SHA256;
            }
            if (hashSizeInBits <= 384) {
                return HashAlgorithmName.SHA384;
            }
            return HashAlgorithmName.SHA512;
        }
    }
}
