using System.Security.Cryptography;
using System.Text;

namespace AesBridge
{
    /// <summary>
    /// The Legacy class provides methods for encryption and decryption
    /// using a legacy AES-compatible format. This format is maintained
    /// for compatibility with older systems and follows the AES Everywhere
    /// implementation. It is not recommended for use in new applications
    /// due to potential security limitations.
    /// </summary>
    public static class Legacy
    {
        /// <summary>
        /// Encrypts plaintext using AES-256-CBC with OpenSSL-compatible format:
        /// base64(Salted__ + salt + ciphertext)
        /// </summary>
        /// <param name="data">Plaintext data to encrypt</param>
        /// <param name="passphrase">Passphrase used to derive key and IV</param>
        /// <returns>Base64-encoded encrypted data (Salted__ + salt + ciphertext)</returns>
        public static string Encrypt(byte[] data, byte[] passphrase)
        {
            var salt = Common.Random(8);
            var (key, iv) = DeriveKeyAndIv(passphrase, salt);
            var dataPadded = Pkcs7Pad(data);

            using var aes = Aes.Create();
            aes.Key = key;
            aes.IV = iv;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.None;

            using var encryptor = aes.CreateEncryptor();
            var ciphertext = encryptor.TransformFinalBlock(dataPadded, 0, dataPadded.Length);

            using var output = new MemoryStream();
            output.Write(Encoding.ASCII.GetBytes("Salted__"), 0, 8);
            output.Write(salt, 0, 8);
            output.Write(ciphertext, 0, ciphertext.Length);

            return Convert.ToBase64String(output.ToArray());
        }

        /// <summary>
        /// Decrypts base64-encoded AES-CBC ciphertext in OpenSSL-compatible format:
        /// base64(Salted__ + salt + ciphertext)
        /// </summary>
        /// <param name="data">Base64-encoded encrypted data</param>
        /// <param name="passphrase">Passphrase used to derive key and IV</param>
        /// <returns>Decrypted raw byte array</returns>
        public static byte[] DecryptToBytes(string data, byte[] passphrase)
        {
            var ct = Convert.FromBase64String(data);
            if (ct.Length < 16 || Encoding.ASCII.GetString(ct, 0, 8) != "Salted__")
                return Array.Empty<byte>();

            var salt = ct.AsSpan(8, 8).ToArray();
            var (key, iv) = DeriveKeyAndIv(passphrase, salt);

            using var aes = Aes.Create();
            aes.Key = key;
            aes.IV = iv;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.None;

            using var decryptor = aes.CreateDecryptor();
            var decrypted = decryptor.TransformFinalBlock(ct, 16, ct.Length - 16);

            return Pkcs7Trim(decrypted);
        }

        /// <summary>
        /// Derives an AES key and IV from the given passphrase and salt using OpenSSL-compatible MD5-based key derivation.
        /// </summary>
        /// <param name="passphrase">Passphrase to use for key derivation</param>
        /// <param name="salt">Salt to use for key derivation</param>
        /// <returns>Tuple containing the derived AES key and IV</returns>
        private static (byte[] key, byte[] iv) DeriveKeyAndIv(byte[] passphrase, byte[] salt)
        {
            using var md5 = MD5.Create();
            var key = new byte[32];
            var iv = new byte[16];

            byte[] dx = Array.Empty<byte>();
            byte[] d = Array.Empty<byte>();

            for (int i = 0; i <= 32; i++)
            {
                dx = Common.Concat(Common.Concat(dx, passphrase), salt);
                dx = md5.ComputeHash(dx);
                d = Common.Concat(d, dx);
            }

            Array.Copy(d, 0, key, 0, 32);
            Array.Copy(d, 32, iv, 0, 16);
            return (key, iv);
        }

        private static byte[] Pkcs7Pad(byte[] data)
        {
            int padLen = 16 - (data.Length % 16);
            var padded = new byte[data.Length + padLen];
            Array.Copy(data, padded, data.Length);
            for (int i = data.Length; i < padded.Length; i++)
                padded[i] = (byte)padLen;
            return padded;
        }

        private static byte[] Pkcs7Trim(byte[] data)
        {
            int padLen = data[^1];
            if (padLen <= 0 || padLen > 16) return data;
            for (int i = data.Length - padLen; i < data.Length; i++)
                if (data[i] != padLen) return data;
            var trimmed = new byte[data.Length - padLen];
            Array.Copy(data, trimmed, trimmed.Length);
            return trimmed;
        }

        /// <summary>
        /// Encrypts plaintext using AES-256-CBC with OpenSSL-compatible format:
        /// base64(Salted__ + salt + ciphertext)
        /// </summary>
        /// <param name="data">Plaintext data to encrypt</param>
        /// <param name="passphrase">Passphrase used to derive key and IV</param>
        /// <returns>Base64-encoded encrypted data (Salted__ + salt + ciphertext)</returns>
        public static string Encrypt(string data, string passphrase)
        {
            Byte[] dataBytes = Encoding.UTF8.GetBytes(data);
            Byte[] passphraseBytes = Encoding.UTF8.GetBytes(passphrase);
            return Encrypt(dataBytes, passphraseBytes);
        }

        /// <summary>
        /// Encrypts plaintext using AES-256-CBC with OpenSSL-compatible format:
        /// base64(Salted__ + salt + ciphertext)
        /// </summary>
        /// <param name="data">Plaintext data to encrypt</param>
        /// <param name="passphrase">Passphrase used to derive key and IV</param>
        /// <returns>Base64-encoded encrypted data (Salted__ + salt + ciphertext)</returns>
        /// Encrypts data using AES-GCM and returns Base64-encoded result.
        /// </summary>
        /// <param name="data">Data to encrypt</param>
        /// <param name="passphrase">Encryption passphrase</param>
        /// <returns>Bese64-encoded encrypted data</returns>
        public static string Encrypt(byte[] data, string passphrase)
        {
            Byte[] passphraseBytes = Encoding.UTF8.GetBytes(passphrase);
            return Encrypt(data, passphraseBytes);
        }

        /// <summary>
        /// Encrypts plaintext using AES-256-CBC with OpenSSL-compatible format:
        /// base64(Salted__ + salt + ciphertext)
        /// </summary>
        /// <param name="data">Plaintext data to encrypt</param>
        /// <param name="passphrase">Passphrase used to derive key and IV</param>
        /// <returns>Base64-encoded encrypted data (Salted__ + salt + ciphertext)</returns>
        public static string Encrypt(string data, byte[] passphrase)
        {
            Byte[] dataBytes = Encoding.UTF8.GetBytes(data);
            return Encrypt(dataBytes, passphrase);
        }

        /// <summary>
        /// Decrypts base64-encoded AES-CBC ciphertext in OpenSSL-compatible format:
        /// base64(Salted__ + salt + ciphertext)
        /// </summary>
        /// <param name="data">Base64-encoded encrypted data</param>
        /// <param name="passphrase">Passphrase used to derive key and IV</param>
        /// <returns>Decrypted raw byte array</returns>
        public static byte[] DecryptToBytes(string data, string passphrase)
        {
            Byte[] passphraseBytes = Encoding.UTF8.GetBytes(passphrase);
            return DecryptToBytes(data, passphraseBytes);
        }

        /// <summary>
        /// Decrypts base64-encoded AES-CBC ciphertext in OpenSSL-compatible format:
        /// base64(Salted__ + salt + ciphertext)
        /// </summary>
        /// <param name="data">Base64-encoded encrypted data</param>
        /// <param name="passphrase">Passphrase used to derive key and IV</param>
        /// <returns>Decrypted raw byte array</returns>
        public static byte[] DecryptToBytes(byte[] data, byte[] passphrase)
        {
            string dataStr = Encoding.UTF8.GetString(data);
            return DecryptToBytes(dataStr, passphrase);
        }

        /// <summary>
        /// Decrypts base64-encoded AES-CBC ciphertext in OpenSSL-compatible format:
        /// base64(Salted__ + salt + ciphertext)
        /// </summary>
        /// <param name="data">Base64-encoded encrypted data</param>
        /// <param name="passphrase">Passphrase used to derive key and IV</param>
        /// <returns>Decrypted raw byte array</returns>
        public static byte[] DecryptToBytes(byte[] data, string passphrase)
        {
            string dataStr = Encoding.UTF8.GetString(data);
            Byte[] passphraseBytes = Encoding.UTF8.GetBytes(passphrase);
            return DecryptToBytes(dataStr, passphraseBytes);
        }

        /// <summary>
        /// Decrypts base64-encoded AES-CBC ciphertext in OpenSSL-compatible format:
        /// base64(Salted__ + salt + ciphertext)
        /// </summary>
        /// <param name="data">Encrypted text to decrypt</param>
        /// <param name="passphrase">Passphrase</param>
        /// <returns>Decrypted data</returns>
        public static string Decrypt(byte[] data, byte[] passphrase)
        {
            return Encoding.UTF8.GetString(DecryptToBytes(data, passphrase));
        }

        /// <summary>
        /// Decrypts base64-encoded AES-CBC ciphertext in OpenSSL-compatible format:
        /// base64(Salted__ + salt + ciphertext)
        /// </summary>
        /// <param name="data">Encrypted text to decrypt</param>
        /// <param name="passphrase">Passphrase</param>
        /// <returns>Decrypted data</returns>
        public static string Decrypt(byte[] data, string passphrase)
        {
            return Encoding.UTF8.GetString(DecryptToBytes(data, passphrase));
        }

        /// <summary>
        /// Decrypts base64-encoded AES-CBC ciphertext in OpenSSL-compatible format:
        /// base64(Salted__ + salt + ciphertext)
        /// </summary>
        /// <param name="data">Encrypted text to decrypt</param>
        /// <param name="passphrase">Passphrase</param>
        /// <returns>Decrypted data</returns>
        public static string Decrypt(string data, byte[] passphrase)
        {
            return Encoding.UTF8.GetString(DecryptToBytes(data, passphrase));
        }

        /// <summary>
        /// Decrypts base64-encoded AES-CBC ciphertext in OpenSSL-compatible format:
        /// base64(Salted__ + salt + ciphertext)
        /// </summary>
        /// <param name="data">Encrypted text to decrypt</param>
        /// <param name="passphrase">Passphrase</param>
        /// <returns>Decrypted data</returns>
        public static string Decrypt(string data, string passphrase)
        {
            return Encoding.UTF8.GetString(DecryptToBytes(data, passphrase));
        }
    }
}
