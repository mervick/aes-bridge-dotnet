using System;
using System.Security.Cryptography;
using System.Text;

namespace AesBridge
{
    internal static class Common
    {
        // public static string ToBase64(this byte[] bytes) => Convert.ToBase64String(bytes);
        // public static byte[] FromBase64(this string base64) => Convert.FromBase64String(base64);

        /// <summary>
        /// Generates a cryptographically secure random byte array.
        /// </summary>
        public static byte[] Random(int length)
        {
            var bytes = new byte[length];
            RandomNumberGenerator.Fill(bytes);
            return bytes;
        }

        /// <summary>
        /// Concatenates the given byte arrays together.
        /// </summary>
        /// <param name="arrays">Arrays to concatenate</param>
        /// <returns>Concatenated array</returns>
        public static byte[] Concat(params byte[][] arrays)
        {
            int length = 0;
            foreach (var arr in arrays) length += arr.Length;
            byte[] result = new byte[length];
            int offset = 0;
            foreach (var arr in arrays)
            {
                Buffer.BlockCopy(arr, 0, result, offset, arr.Length);
                offset += arr.Length;
            }
            return result;
        }

        /// <summary>
        /// Copies a slice of the given array into a new array.
        /// </summary>
        /// <param name="data">Array to slice</param>
        /// <param name="offset">Starting offset of the slice</param>
        /// <param name="length">Length of the slice</param>
        /// <returns>New array containing the sliced data</returns>
        public static byte[] Slice(this byte[] data, int offset, int length)
        {
            byte[] result = new byte[length];
            Buffer.BlockCopy(data, offset, result, 0, length);
            return result;
        }
    }
}
