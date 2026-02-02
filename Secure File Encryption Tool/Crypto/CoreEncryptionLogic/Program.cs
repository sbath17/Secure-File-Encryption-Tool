using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace SecureFileEncryptor.Crypto
{
    public static class CryptoCore
    {
        private const int SaltSize = 16;
        private const int KeySize = 32; // 256-bit
        private const int NonceSize = 12;
        private const int TagSize = 16;
        private const int Iterations = 200_000;

        private static byte[] DeriveKey(string password, byte[] salt)
        {
            using var pbkdf2 = new Rfc2898DeriveBytes(
                password,
                salt,
                Iterations,
                HashAlgorithmName.SHA256);

            return pbkdf2.GetBytes(KeySize);
        }

        public static void EncryptFile(string password, string inputPath, string outputPath)
        {
            byte[] salt = RandomNumberGenerator.GetBytes(SaltSize);
            byte[] key = DeriveKey(password, salt);
            byte[] nonce = RandomNumberGenerator.GetBytes(NonceSize);

            byte[] plaintext = File.ReadAllBytes(inputPath);
            byte[] ciphertext = new byte[plaintext.Length];
            byte[] tag = new byte[TagSize];

            using var aes = new AesGcm(key);
            aes.Encrypt(nonce, plaintext, ciphertext, tag);

            using var fs = new FileStream(outputPath, FileMode.Create);
            fs.Write(salt);
            fs.Write(nonce);
            fs.Write(ciphertext);
            fs.Write(tag);
        }

        public static void DecryptFile(string password, string inputPath, string outputPath)
        {
            byte[] data = File.ReadAllBytes(inputPath);

            byte[] salt = data[..SaltSize];
            byte[] nonce = data[SaltSize..(SaltSize + NonceSize)];

            int cipherStart = SaltSize + NonceSize;
            int cipherLength = data.Length - cipherStart - TagSize;

            byte[] ciphertext = data[cipherStart..(cipherStart + cipherLength)];
            byte[] tag = data[(data.Length - TagSize)..];

            byte[] key = DeriveKey(password, salt);
            byte[] plaintext = new byte[cipherLength];

            using var aes = new AesGcm(key);
            aes.Decrypt(nonce, ciphertext, tag, plaintext);

            File.WriteAllBytes(outputPath, plaintext);
        }
    }
}