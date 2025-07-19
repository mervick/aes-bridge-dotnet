using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace AesBridge
{
    /// <summary>
    /// Provides encryption and decryption using AES-256 CBC + HMAC
    /// </summary>
    public static class Cbc
    {
        /// <summary>
        /// Derives AES and HMAC keys from the given passphrase and salt using PBKDF2 with SHA256.
        /// </summary>
        /// <param name="passphrase">Encryption passphrase</param>
        /// <param name="salt">Salt to use for key derivation</param>
        /// <returns>Tuple containing the AES key and HMAC key</returns>
        private static (byte[] key, byte[] hmac) DeriveKeys(byte[] passphrase, byte[] salt)
        {
            using var kdf = new Rfc2898DeriveBytes(passphrase, salt, 100_000, HashAlgorithmName.SHA256);
            var keyData = kdf.GetBytes(64);
            return (keyData[..32], keyData[32..]);
        }

        /// <summary>
        /// Encrypts the given data using AES-CBC with HMAC authentication.
        /// </summary>
        /// <param name="data">Data to encrypt</param>
        /// <param name="passphrase">Encryption passphrase</param>
        /// <returns>Encrypted binary data: salt + IV + ciphertext + HMAC</returns>
        public static byte[] EncryptBin(byte[] data, byte[] passphrase)
        {
            var salt = Common.Random(16);
            var iv = Common.Random(16);
            var (aesKey, hmacKey) = DeriveKeys(passphrase, salt);

            byte[] padded = Pkcs7Pad(data, 16);

            using var aes = Aes.Create();
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.None;
            aes.Key = aesKey;
            aes.IV = iv;

            using var encryptor = aes.CreateEncryptor();
            byte[] ciphertext = encryptor.TransformFinalBlock(padded, 0, padded.Length);

            using var hmac = new HMACSHA256(hmacKey);
            byte[] tag = hmac.ComputeHash(Common.Concat(iv, ciphertext));

            return Common.Concat(salt, iv, ciphertext, tag);
        }

        /// <summary>
        /// Decrypts binary data encrypted with EncryptBin().
        /// </summary>
        /// <param name="data">Encrypted binary: salt + IV + ciphertext + HMAC</param>
        /// <param name="passphrase">Encryption passphrase</param>
        /// <returns>Decrypted original plaintext</returns>
        public static byte[] DecryptBin(byte[] data, byte[] passphrase)
        {
            var salt = data[..16];
            var iv = data.Slice(16, 16);
            var tag = data[^32..];
            var ciphertext = data.Slice(16 + 16, data.Length - 16 - 16 - 32);

            var (aesKey, hmacKey) = DeriveKeys(passphrase, salt);

            using var hmac = new HMACSHA256(hmacKey);
            byte[] expectedTag = hmac.ComputeHash(Common.Concat(iv, ciphertext));
            CryptographicOperations.FixedTimeEquals(expectedTag, tag);

            using var aes = Aes.Create();
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.None;
            aes.Key = aesKey;
            aes.IV = iv;

            using var decryptor = aes.CreateDecryptor();
            byte[] padded = decryptor.TransformFinalBlock(ciphertext, 0, ciphertext.Length);

            return Pkcs7Unpad(padded, 16);
        }

        /// <summary>
        /// Applies PKCS#7 padding to the input data to ensure its length is a multiple of the block size.
        /// </summary>
        /// <param name="data">The input data to pad.</param>
        /// <param name="blockSize">The block size to pad the data to.</param>
        /// <returns>The padded byte array.</returns>
        private static byte[] Pkcs7Pad(byte[] data, int blockSize)
        {
            int padLen = blockSize - (data.Length % blockSize);
            byte[] padded = new byte[data.Length + padLen];
            Buffer.BlockCopy(data, 0, padded, 0, data.Length);
            for (int i = data.Length; i < padded.Length; i++) padded[i] = (byte)padLen;
            return padded;
        }

        /// <summary>
        /// Removes PKCS#7 padding from the input data.
        /// </summary>
        /// <param name="data">The input data to unpad.</param>
        /// <param name="blockSize">The block size to unpad the data to.</param>
        /// <returns>The unpadded byte array.</returns>
        /// <exception cref="CryptographicException">If the padding is invalid.</exception>
        private static byte[] Pkcs7Unpad(byte[] data, int blockSize)
        {
            int padLen = data[^1];
            if (padLen <= 0 || padLen > blockSize)
                throw new CryptographicException("Invalid padding");
            return data[..^padLen];
        }

        /// <summary>
        /// Encrypts data using AES-256 in CBC mode.
        /// </summary>
        /// <param name="plaintext">Data to encrypt</param>
        /// <param name="passphrase">Encryption passphrase</param>
        /// <returns>Encrypted data in format: salt (16) + IV (16) + ciphertext (N) + HMAC (32)</returns>
        public static byte[] EncryptBin(byte[] data, string passphrase)
        {
            Byte[] passphraseBytes = Encoding.UTF8.GetBytes(passphrase);
            return EncryptBin(data, passphraseBytes);
        }

        /// <summary>
        /// Encrypts data using AES-256 in CBC mode.
        /// </summary>
        /// <param name="plaintext">Data to encrypt</param>
        /// <param name="passphrase">Encryption passphrase</param>
        /// <returns>Encrypted data in format: salt (16) + IV (16) + ciphertext (N) + HMAC (32)</returns>
        public static byte[] EncryptBin(string data, byte[] passphrase)
        {
            Byte[] dataBytes = Encoding.UTF8.GetBytes(data);
            return EncryptBin(dataBytes, passphrase);
        }

        /// <summary>
        /// Encrypts data using AES-256 in CBC mode.
        /// </summary>
        /// <param name="plaintext">Data to encrypt</param>
        /// <param name="passphrase">Encryption passphrase</param>
        /// <returns>Encrypted data in format: salt (16) + IV (16) + ciphertext (N) + HMAC (32)</returns>
        public static byte[] EncryptBin(string data, string passphrase)
        {
            Byte[] dataBytes = Encoding.UTF8.GetBytes(data);
            Byte[] passphraseBytes = Encoding.UTF8.GetBytes(passphrase);
            return EncryptBin(dataBytes, passphraseBytes);
        }

        /// <summary>
        /// Decrypts data encrypted by EncryptBin().
        /// </summary>
        /// <param name="data">Encrypted data</param>
        /// <param name="passphrase">Encryption passphrase</param>
        /// <returns>Decrypted data</returns>
        public static byte[] DecryptBin(byte[] data, string passphrase)
        {
            Byte[] passphraseBytes = Encoding.UTF8.GetBytes(passphrase);
            return DecryptBin(data, passphraseBytes);
        }

        /// <summary>
        /// Encrypts data using AES-CBC and returns Base64-encoded result.
        /// </summary>
        /// <param name="plaintext">Data to encrypt</param>
        /// <param name="passphrase">Encryption passphrase</param>
        /// <returns>Bese64-encoded encrypted data</returns>
        public static string Encrypt(byte[] data, byte[] passphrase)
        {
            Byte[] encrypted = EncryptBin(data, passphrase);
            return Convert.ToBase64String(encrypted);
        }

        /// <summary>
        /// Encrypts data using AES-CBC and returns Base64-encoded result.
        /// </summary>
        /// <param name="plaintext">Data to encrypt</param>
        /// <param name="passphrase">Encryption passphrase</param>
        /// <returns>Bese64-encoded encrypted data</returns>
        public static string Encrypt(byte[] data, string passphrase)
        {
            Byte[] encrypted = EncryptBin(data, passphrase);
            return Convert.ToBase64String(encrypted);
        }

        /// <summary>
        /// Encrypts data using AES-CBC and returns Base64-encoded result.
        /// </summary>
        /// <param name="plaintext">Data to encrypt</param>
        /// <param name="passphrase">Encryption passphrase</param>
        /// <returns>Bese64-encoded encrypted data</returns>
        public static string Encrypt(string data, byte[] passphrase)
        {
            Byte[] encrypted = EncryptBin(data, passphrase);
            return Convert.ToBase64String(encrypted);
        }

        /// <summary>
        /// Encrypts data using AES-CBC and returns Base64-encoded result.
        /// </summary>
        /// <param name="plaintext">Data to encrypt</param>
        /// <param name="passphrase">Encryption passphrase</param>
        /// <returns>Bese64-encoded encrypted data</returns>
        public static string Encrypt(string data, string passphrase)
        {
            Byte[] encrypted = EncryptBin(data, passphrase);
            return Convert.ToBase64String(encrypted);
        }

        /// <summary>
        /// Decrypts Base64-encoded data encrypted by Encrypt().
        /// </summary>
        /// <param name="data">Base64-encode encrypted data</param>
        /// <param name="passphrase">Encryption passphrase</param>
        /// <returns>Decrypted data</returns>
        public static byte[] Decrypt(byte[] data, byte[] passphrase)
        {
            string dataStr = Encoding.UTF8.GetString(data);
            Byte[] dataBytes = Convert.FromBase64String(dataStr);
            return DecryptBin(dataBytes, passphrase);
        }

        /// <summary>
        /// Decrypts Base64-encoded data encrypted by Encrypt().
        /// </summary>
        /// <param name="data">Base64-encode encrypted data</param>
        /// <param name="passphrase">Encryption passphrase</param>
        /// <returns>Decrypted data</returns>
        public static byte[] Decrypt(byte[] data, string passphrase)
        {
            string dataStr = Encoding.UTF8.GetString(data);
            Byte[] dataBytes = Convert.FromBase64String(dataStr);
            return DecryptBin(dataBytes, passphrase);
        }

        /// <summary>
        /// Decrypts Base64-encoded data encrypted by Encrypt().
        /// </summary>
        /// <param name="data">Base64-encode encrypted data</param>
        /// <param name="passphrase">Encryption passphrase</param>
        /// <returns>Decrypted data</returns>
        public static byte[] Decrypt(string data, byte[] passphrase)
        {
            Byte[] dataBytes = Convert.FromBase64String(data);
            return DecryptBin(dataBytes, passphrase);
        }

        /// <summary>
        /// Decrypts Base64-encoded data encrypted by Encrypt().
        /// </summary>
        /// <param name="data">Base64-encode encrypted data</param>
        /// <param name="passphrase">Encryption passphrase</param>
        /// <returns>Decrypted data</returns>
        public static byte[] Decrypt(string data, string passphrase)
        {
            Byte[] dataBytes = Convert.FromBase64String(data);
            return DecryptBin(dataBytes, passphrase);
        }
    }
}
