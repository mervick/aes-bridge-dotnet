using System.Security.Cryptography;
using System.Text;

namespace AesBridge
{
    /// <summary>
    /// Provides encryption and decryption using AES-256 in GCM mode.
    /// </summary>
    public static class Gcm
    {
        /// <summary>
        /// Creates a new instance of <see cref="AesGcm"/> initialized with the given key.
        /// </summary>
        /// <param name="key">The 256-bit key to use for encryption and decryption.</param>
        /// <returns>A new <see cref="AesGcm"/> instance.</returns>
        /// <remarks>
        /// </remarks>
        private static AesGcm CreateAesGcm(byte[] key)
        {
            #if NET8_0_OR_GREATER
                return new AesGcm(key, 16);  // .NET 8+
            #else
                return new AesGcm(key);  // .NET 6/7
            #endif
        }

        /// <summary>
        /// Derives a 256-bit key from the passphrase and salt using PBKDF2 with SHA256.
        /// </summary>
        private static byte[] DeriveKey(byte[] passphrase, byte[] salt)
        {
            using var kdf = new Rfc2898DeriveBytes(passphrase, salt, 100_000, HashAlgorithmName.SHA256);
            return kdf.GetBytes(32); // AES-256
        }

        /// <summary>
        /// Encrypts data using AES-256 in GCM mode.
        /// </summary>
        /// <param name="data">Data to encrypt</param>
        /// <param name="passphrase">Encryption passphrase</param>
        /// <returns>Encrypted data in format: salt(16) + nonce(12) + ciphertext + tag(16)</returns>
        public static byte[] EncryptBin(byte[] data, byte[] passphrase)
        {
            var salt = Common.Random(16);
            var nonce = Common.Random(12);
            var ciphertext = new byte[data.Length];
            var tag = new byte[16];
            var key = DeriveKey(passphrase, salt);

            using (var aesGcm = CreateAesGcm(key))
            {
                aesGcm.Encrypt(nonce, data, ciphertext, tag);
            }

            var result = new byte[salt.Length + nonce.Length + ciphertext.Length + tag.Length];
            Buffer.BlockCopy(salt, 0, result, 0, 16);
            Buffer.BlockCopy(nonce, 0, result, 16, 12);
            Buffer.BlockCopy(ciphertext, 0, result, 28, ciphertext.Length);
            Buffer.BlockCopy(tag, 0, result, 28 + ciphertext.Length, 16);

            return result;
        }

        /// <summary>
        /// Decrypts data encrypted by EncryptBin().
        /// </summary>
        /// <param name="data">Encrypted data</param>
        /// <param name="passphrase">Encryption passphrase</param>
        /// <returns>Decrypted data</returns>
        public static byte[] DecryptBin(byte[] data, byte[] passphrase)
        {
            var salt = data[..16];
            var nonce = data[16..28];
            var tag = data[^16..];
            var ciphertext = data[28..^16];
            var plaintext = new byte[ciphertext.Length];
            var key = DeriveKey(passphrase, salt);

            using (var aesGcm = CreateAesGcm(key))
            {
                aesGcm.Decrypt(nonce, ciphertext, tag, plaintext);
            }

            return plaintext;
        }

        /// <summary>
        /// Encrypts data using AES-256 in GCM mode.
        /// </summary>
        /// <param name="data">Data to encrypt</param>
        /// <param name="passphrase">Encryption passphrase</param>
        /// <returns>Encrypted data in format: salt(16) + nonce(12) + ciphertext + tag(16)</returns>
        public static byte[] EncryptBin(byte[] data, string passphrase)
        {
            Byte[] passphraseBytes = Encoding.UTF8.GetBytes(passphrase);
            return EncryptBin(data, passphraseBytes);
        }

        /// <summary>
        /// Encrypts data using AES-256 in GCM mode.
        /// </summary>
        /// <param name="data">Data to encrypt</param>
        /// <param name="passphrase">Encryption passphrase</param>
        /// <returns>Encrypted data in format: salt(16) + nonce(12) + ciphertext + tag(16)</returns>
        public static byte[] EncryptBin(string data, byte[] passphrase)
        {
            Byte[] dataBytes = Encoding.UTF8.GetBytes(data);
            return EncryptBin(dataBytes, passphrase);
        }

        /// <summary>
        /// Encrypts data using AES-256 in GCM mode.
        /// </summary>
        /// <param name="data">Data to encrypt</param>
        /// <param name="passphrase">Encryption passphrase</param>
        /// <returns>Encrypted data in format: salt(16) + nonce(12) + ciphertext + tag(16)</returns>
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
        /// Encrypts data using AES-GCM and returns Base64-encoded result.
        /// </summary>
        /// <param name="data">Data to encrypt</param>
        /// <param name="passphrase">Encryption passphrase</param>
        /// <returns>Bese64-encoded encrypted data</returns>
        public static string Encrypt(byte[] data, byte[] passphrase)
        {
            Byte[] encrypted = EncryptBin(data, passphrase);
            return Convert.ToBase64String(encrypted);
        }

        /// <summary>
        /// Encrypts data using AES-GCM and returns Base64-encoded result.
        /// </summary>
        /// <param name="data">Data to encrypt</param>
        /// <param name="passphrase">Encryption passphrase</param>
        /// <returns>Bese64-encoded encrypted data</returns>
        public static string Encrypt(byte[] data, string passphrase)
        {
            Byte[] encrypted = EncryptBin(data, passphrase);
            return Convert.ToBase64String(encrypted);
        }

        /// <summary>
        /// Encrypts data using AES-GCM and returns Base64-encoded result.
        /// </summary>
        /// <param name="data">Data to encrypt</param>
        /// <param name="passphrase">Encryption passphrase</param>
        /// <returns>Bese64-encoded encrypted data</returns>
        public static string Encrypt(string data, byte[] passphrase)
        {
            Byte[] encrypted = EncryptBin(data, passphrase);
            return Convert.ToBase64String(encrypted);
        }

        /// <summary>
        /// Encrypts data using AES-GCM and returns Base64-encoded result.
        /// </summary>
        /// <param name="data">Data to encrypt</param>
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
