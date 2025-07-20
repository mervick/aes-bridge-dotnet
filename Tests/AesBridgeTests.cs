using NUnit.Framework;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Linq;
using AesBridge;


namespace AesBridgeTests
{
    internal class TestData
    {
        [JsonProperty("plaintext")]
        public List<string>? Plaintext { get; set; }

        [JsonProperty("hex")]
        public List<string>? Hex { get; set; }
    }

    internal class DecryptCase
    {
        [JsonProperty("id")]
        public required string Id { get; set; }

        [JsonProperty("plaintext")]
        public string? Plaintext { get; set; }
        [JsonProperty("hex")]
        public string? Hex { get; set; }

        [JsonProperty("passphrase")]
        public required string Passphrase { get; set; }

        [JsonProperty("encrypted-cbc")]
        public string? EncryptedCbc { get; set; }

        [JsonProperty("encrypted-gcm")]
        public string? EncryptedGcm { get; set; }

        [JsonProperty("encrypted-legacy")]
        public string? EncryptedLegacy { get; set; }
    }

    internal class RootTestData
    {
        [JsonProperty("testdata")]
        public required TestData TestDataSections { get; set; }

        [JsonProperty("decrypt")]
        public required List<DecryptCase> DecryptCases { get; set; }
    }

    internal static class StringExtensions
    {
        public static byte[] HexStringToByteArray(this string hex)
        {
            if (hex.Length % 2 == 1)
                throw new ArgumentException("The hex string cannot have an odd number of digits");

            byte[] arr = new byte[hex.Length >> 1];

            for (int i = 0; i < hex.Length >> 1; ++i)
            {
                arr[i] = (byte)((GetHexVal(hex[i << 1]) << 4) + (GetHexVal(hex[(i << 1) + 1])));
            }

            return arr;
        }

        private static int GetHexVal(char hex)
        {
            int val = (int)hex;
            return val - (val < 58 ? 48 : (val < 97 ? 55 : 87));
        }
    }

    [TestFixture]
    public class AesBridgeTests
    {
        private static bool IsLoadedDynamicTests = false;

        private static RootTestData? _rootTestData;

        // Load test data once for all tests
        // [OneTimeSetUp]
        // [SetUp]
        private static void LoadDynamicTests()
        {
            if (IsLoadedDynamicTests)
            {
                return;
            }

            IsLoadedDynamicTests = true;

            // Assert.Fail("LoadDynamicTests");
            string filePath = Path.Combine(TestContext.CurrentContext.TestDirectory, "test_data.json");
            string jsonContent = File.ReadAllText(filePath);
            var rootTestData = JsonConvert.DeserializeObject<RootTestData>(jsonContent);

            _rootTestData = rootTestData ?? throw new InvalidOperationException($"Failed to load test data from {filePath}");
        }

        // Providers for dynamic test data
        private static IEnumerable<object[]> GetPlaintextCases()
        {
            LoadDynamicTests();
            // Assert.Fail("GetPlaintextCases");
            if (_rootTestData == null)
            {
                Assert.Fail("Test data not loaded. Ensure LoadDynamicTests is called before running tests.");
                yield break;
            }
            if (_rootTestData.TestDataSections.Plaintext == null)
            {
                yield break;
            }
            foreach (var text in _rootTestData.TestDataSections.Plaintext)
            {
                yield return new object[] { Encoding.UTF8.GetBytes(text) };
            }
        }

        private static IEnumerable<object[]> GetHexCases()
        {
            LoadDynamicTests();
            if (_rootTestData == null)
            {
                Assert.Fail("Test data not loaded. Ensure LoadDynamicTests is called before running tests.");
                yield break;
            }
            if (_rootTestData.TestDataSections.Hex == null)
            {
                yield break;
            }
            foreach (var hex in _rootTestData.TestDataSections.Hex)
            {
                yield return new object[] { hex.HexStringToByteArray() };
            }
        }

        private static IEnumerable<object[]> GetDecryptCases()
        {
            LoadDynamicTests();
            if (_rootTestData == null)
            {
                Assert.Fail("Test data not loaded. Ensure LoadDynamicTests is called before running tests.");
                yield break;
            }

            foreach (var testCase in _rootTestData.DecryptCases)
            {
                if (testCase.Plaintext == null && string.IsNullOrEmpty(testCase.Hex))
                {
                    continue;
                }

                if (string.IsNullOrEmpty(testCase.EncryptedCbc) && string.IsNullOrEmpty(testCase.EncryptedGcm) &&
                    string.IsNullOrEmpty(testCase.EncryptedLegacy))
                {
                    continue;
                }

                byte[]? expectedPlaintextBytes = null;

                if (testCase.Plaintext != null)
                {
                    expectedPlaintextBytes = Encoding.UTF8.GetBytes(testCase.Plaintext);
                }
                else if (!string.IsNullOrEmpty(testCase.Hex))
                {
                    expectedPlaintextBytes = testCase.Hex.HexStringToByteArray();
                }

                if (expectedPlaintextBytes == null)
                {
                    continue;
                }

                if (!string.IsNullOrEmpty(testCase.EncryptedCbc))
                {
                    yield return new object[] { "CBC", testCase.EncryptedCbc,
                        testCase.Passphrase, expectedPlaintextBytes, testCase.Id };
                }
                if (!string.IsNullOrEmpty(testCase.EncryptedGcm))
                {
                    yield return new object[] { "GCM", testCase.EncryptedGcm,
                        testCase.Passphrase, expectedPlaintextBytes, testCase.Id };
                }
                if (!string.IsNullOrEmpty(testCase.EncryptedLegacy))
                {
                    yield return new object[] { "Legacy", testCase.EncryptedLegacy,
                        testCase.Passphrase, expectedPlaintextBytes, testCase.Id };
                }
            }
        }

        [TestCaseSource(nameof(GetPlaintextCases))]
        [TestCaseSource(nameof(GetHexCases))]
        public void TestEncryptDecryptCbc(byte[] value)
        {
            string encrypted = AesBridge.Cbc.Encrypt(value, value);
            Assert.That(encrypted, Is.Not.Null, "Encryption result should not be null");
            Assert.That(encrypted, Is.Not.Empty, "Encryption result should not be empty");
            Assert.That(encrypted.Length, Is.GreaterThan(0), "Encryption result should not be empty");
            byte[] decrypted = AesBridge.Cbc.Decrypt(encrypted, value);
            Assert.That(decrypted, Is.EqualTo(value), "CBC encryption/decryption failed");
        }

        [TestCaseSource(nameof(GetPlaintextCases))]
        [TestCaseSource(nameof(GetHexCases))]
        public void TestEncryptDecryptGcm(byte[] value)
        {
            string encrypted = AesBridge.Gcm.Encrypt(value, value);
            Assert.That(encrypted, Is.Not.Null, "Encryption result should not be null");
            Assert.That(encrypted, Is.Not.Empty, "Encryption result should not be empty");
            Assert.That(encrypted.Length, Is.GreaterThan(0), "Encryption result should not be empty");
            byte[] decrypted = AesBridge.Gcm.Decrypt(encrypted, value);
            Assert.That(decrypted, Is.EqualTo(value), "GCM encryption/decryption failed");
        }

        [TestCaseSource(nameof(GetPlaintextCases))]
        [TestCaseSource(nameof(GetHexCases))]
        public void TestEncryptDecryptLegacy(byte[] value)
        {
            string encrypted = AesBridge.Legacy.Encrypt(value, value);
            Assert.That(encrypted, Is.Not.Null, "Encryption result should not be null");
            Assert.That(encrypted, Is.Not.Empty, "Encryption result should not be empty");
            Assert.That(encrypted.Length, Is.GreaterThan(0), "Encryption result should not be empty");
            byte[] decrypted = AesBridge.Legacy.DecryptToBytes(encrypted, value);
            Assert.That(decrypted, Is.EqualTo(value), "Legacy encryption/decryption failed");
        }

        [TestCaseSource(nameof(GetDecryptCases))]
        public void TestDecryptPredefinedCases(string type, string encrypted, string passphrase, byte[] expectedPlaintext, string testId)
        {
            byte[]? decrypted = null;
            switch (type)
            {
                case "CBC":
                    decrypted = AesBridge.Cbc.Decrypt(encrypted, passphrase);
                    break;
                case "GCM":
                    decrypted = AesBridge.Gcm.Decrypt(encrypted, passphrase);
                    break;
                case "Legacy":
                    decrypted = AesBridge.Legacy.DecryptToBytes(encrypted, passphrase);
                    break;
                default:
                    Assert.Fail($"Unknown decryption type: {type}");
                    break;
            }

            Assert.That(decrypted, Is.EqualTo(expectedPlaintext), $"Decryption failed for {type} test case: {testId}");
        }
    }
}
