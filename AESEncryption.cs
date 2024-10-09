using System;
using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto.Modes;

namespace BouncyCastle_Cryption
{
    class AESEncryption
    {
        public static void EncryptDecrypt()
        {
            // Original data to encrypt
            string originalText = "Hello, World!";
            byte[] inputData = Encoding.UTF8.GetBytes(originalText);

            // Generate AES key and IV
            byte[] aesKey = GenerateAesKey(256); // Using 256-bit AES key
            byte[] aesIv = GenerateIv(128); // Using 128-bit IV (AES block size)

            // Encrypt the data
            byte[] encryptedData = Encrypt(inputData, aesKey, aesIv);
            Console.WriteLine("Encrypted Data: " + Convert.ToBase64String(encryptedData));

            // Decrypt the data
            byte[] decryptedData = Decrypt(encryptedData, aesKey, aesIv);
            string decryptedText = Encoding.UTF8.GetString(decryptedData);
            Console.WriteLine("Decrypted Text: " + decryptedText);
        }

        // Method to generate a random AES key of the specified size (e.g., 128, 192, 256 bits)
        public static byte[] GenerateAesKey(int keySize)
        {
            var randomGenerator = new SecureRandom();
            byte[] key = new byte[keySize / 8]; // 128 bits = 16 bytes
            randomGenerator.NextBytes(key);
            return key;
        }

        // Method to generate a random IV (Initialization Vector) for AES encryption
        public static byte[] GenerateIv(int blockSize)
        {
            var randomGenerator = new SecureRandom();
            byte[] iv = new byte[blockSize / 8]; // Block size for AES is typically 128 bits
            randomGenerator.NextBytes(iv);
            return iv;
        }

        // AES Encryption method
        public static byte[] Encrypt(byte[] inputData, byte[] key, byte[] iv)
        {
            // Create AES engine and CBC block cipher mode with PKCS7 padding
            var aesEngine = new AesEngine();
            var cipher = new PaddedBufferedBlockCipher(new CbcBlockCipher(aesEngine), new Pkcs7Padding());

            // Initialize cipher for encryption
            cipher.Init(true, new ParametersWithIV(new KeyParameter(key), iv));

            // Encrypt the data
            byte[] encryptedData = new byte[cipher.GetOutputSize(inputData.Length)];
            int length = cipher.ProcessBytes(inputData, 0, inputData.Length, encryptedData, 0);
            cipher.DoFinal(encryptedData, length);

            return encryptedData;
        }

        // AES Decryption method
        public static byte[] Decrypt(byte[] encryptedData, byte[] key, byte[] iv)
        {
            // Create AES engine and CBC block cipher mode with PKCS7 padding
            var aesEngine = new AesEngine();
            var cipher = new PaddedBufferedBlockCipher(new CbcBlockCipher(aesEngine), new Pkcs7Padding());

            // Initialize cipher for decryption
            cipher.Init(false, new ParametersWithIV(new KeyParameter(key), iv));

            // Decrypt the data
            byte[] decryptedData = new byte[cipher.GetOutputSize(encryptedData.Length)];
            int length = cipher.ProcessBytes(encryptedData, 0, encryptedData.Length, decryptedData, 0);
            cipher.DoFinal(decryptedData, length);

            return decryptedData;
        }
    }
}
