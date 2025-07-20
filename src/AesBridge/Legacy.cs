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
        /// Encrypt input text with the password using random salt.
        /// Returns base64 decoded encrypted string.
        /// </summary>
        /// <param name="raw">Input text to encrypt</param>
        /// <param name="passphrase">Passphrase</param>
        public static string Encrypt(string raw, string passphrase)
        {
            return Encrypt(Encoding.UTF8.GetBytes(raw), passphrase);
        }

        /// <summary>
        /// Encrypts plaintext using AES-256-CBC with OpenSSL-compatible format:
        /// base64(Salted__ + salt + ciphertext)
        /// </summary>
        /// <param name="raw">Plaintext data to encrypt</param>
        /// <param name="passphrase">Passphrase used to derive key and IV</param>
        /// <returns>Base64-encoded encrypted data (Salted__ + salt + ciphertext)</returns>
        public static string Encrypt(byte[] raw, string passphrase)
        {
            var salt = Common.Random(8);
            var (key, iv) = DeriveKeyAndIv(passphrase, salt);
            var data = Pkcs7Pad(raw);

            using var aes = Aes.Create();
            aes.Key = key;
            aes.IV = iv;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.None;

            using var encryptor = aes.CreateEncryptor();
            var ciphertext = encryptor.TransformFinalBlock(data, 0, data.Length);

            using var output = new MemoryStream();
            output.Write(Encoding.ASCII.GetBytes("Salted__"), 0, 8);
            output.Write(salt, 0, 8);
            output.Write(ciphertext, 0, ciphertext.Length);

            return Convert.ToBase64String(output.ToArray());
        }

        /// <summary>
        /// Derypt encrypted text with the password using random salt.
        /// Returns the decrypted string.
        /// </summary>
        /// <param name="encrypted">Encrypted text to decrypt</param>
        /// <param name="passphrase">Passphrase</param>
        public static string Decrypt(string encrypted, string passphrase)
        {
            return Encoding.UTF8.GetString(DecryptToBytes(encrypted, passphrase));
        }

        /// <summary>
        /// Decrypts base64-encoded AES-CBC ciphertext in OpenSSL-compatible format:
        /// base64(Salted__ + salt + ciphertext)
        /// </summary>
        /// <param name="encrypted">Base64-encoded encrypted data</param>
        /// <param name="passphrase">Passphrase used to derive key and IV</param>
        /// <returns>Decrypted raw byte array</returns>
        public static byte[] DecryptToBytes(string encrypted, string passphrase)
        {
            var ct = Convert.FromBase64String(encrypted);
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
        /// <param name="password">Passphrase to use for key derivation</param>
        /// <param name="salt">Salt to use for key derivation</param>
        /// <returns>Tuple containing the derived AES key and IV</returns>
        private static (byte[] key, byte[] iv) DeriveKeyAndIv(string password, byte[] salt)
        {
            using var md5 = MD5.Create();
            var data = Encoding.UTF8.GetBytes(password);

            var key = new byte[32];
            var iv = new byte[16];

            byte[] dx = Array.Empty<byte>();
            byte[] d = Array.Empty<byte>();

            for (int i = 0; i <= 32; i++)
            {
                dx = Common.Concat(Common.Concat(dx, data), salt);
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

        private static byte[] Combine(byte[] a, byte[] b)
        {
            var result = new byte[a.Length + b.Length];
            Buffer.BlockCopy(a, 0, result, 0, a.Length);
            Buffer.BlockCopy(b, 0, result, a.Length, b.Length);
            return result;
        }
    }
}
