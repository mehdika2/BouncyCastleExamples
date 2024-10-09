using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using System;
using System.IO;
using System.Text;

namespace BouncyCastle_Cryption
{
    class RSAEncryption
    {
        public static void EncryptDecrypt()
        {
            AsymmetricKeyParameter privateKey = LoadPrivateKeyFromPem("private_key.pem");
            AsymmetricKeyParameter publicKey = LoadPublicKeyFromPem("public_key.pem");

            string originalText = "Hello, RSA!";
            byte[] dataToEncrypt = Encoding.UTF8.GetBytes(originalText);

            // Encrypt with public key (normal RSA encryption)
            byte[] encryptedData = EncryptWithPublicKey(publicKey, dataToEncrypt);
            Console.WriteLine("Data encrypted with public key.");

            // Decrypt with private key
            byte[] decryptedData = DecryptWithPrivateKey(privateKey, encryptedData);
            Console.WriteLine($"Decrypted data: {Encoding.UTF8.GetString(decryptedData)}");

            // Encrypt with private key (signature-like)
            byte[] signedData = EncryptWithPrivateKey(privateKey, dataToEncrypt);
            Console.WriteLine("Data encrypted with private key.");

            // Decrypt with public key
            byte[] decryptedSignedData = DecryptWithPublicKey(publicKey, signedData);
            Console.WriteLine($"Decrypted data (signed): {Encoding.UTF8.GetString(decryptedSignedData)}");
        }

        public static byte[] EncryptWithPublicKey(AsymmetricKeyParameter publicKey, byte[] data)
        {
            var encryptEngine = new Pkcs1Encoding(new RsaEngine());
            encryptEngine.Init(true, publicKey); // true = encryption mode
            return encryptEngine.ProcessBlock(data, 0, data.Length);
        }

        // Decrypt data using the private key
        public static byte[] DecryptWithPrivateKey(AsymmetricKeyParameter privateKey, byte[] encryptedData)
        {
            var decryptEngine = new Pkcs1Encoding(new RsaEngine());
            decryptEngine.Init(false, privateKey); // false = decryption mode
            return decryptEngine.ProcessBlock(encryptedData, 0, encryptedData.Length);
        }

        // Encrypt data using the private key (like signing)
        public static byte[] EncryptWithPrivateKey(AsymmetricKeyParameter privateKey, byte[] data)
        {
            var encryptEngine = new Pkcs1Encoding(new RsaEngine());
            encryptEngine.Init(true, privateKey); // true = encryption mode
            return encryptEngine.ProcessBlock(data, 0, data.Length);
        }

        // Decrypt data using the public key
        public static byte[] DecryptWithPublicKey(AsymmetricKeyParameter publicKey, byte[] encryptedData)
        {
            var decryptEngine = new Pkcs1Encoding(new RsaEngine());
            decryptEngine.Init(false, publicKey); // false = decryption mode
            return decryptEngine.ProcessBlock(encryptedData, 0, encryptedData.Length);
        }



        // Load private key from PEM file
        public static AsymmetricKeyParameter LoadPrivateKeyFromPem(string pemFilePath)
        {
            using (var reader = File.OpenText(pemFilePath))
            {
                PemReader pemReader = new PemReader(reader);
                var keyPair = pemReader.ReadObject();

                if (keyPair is AsymmetricCipherKeyPair)
                {
                    // If it's a key pair, return the private key
                    return ((AsymmetricCipherKeyPair)keyPair).Private;
                }
                else
                {
                    throw new InvalidCastException("PEM file does not contain a valid private key");
                }
            }
        }

        // Load public key from PEM file
        public static AsymmetricKeyParameter LoadPublicKeyFromPem(string pemFilePath)
        {
            using (var reader = File.OpenText(pemFilePath))
            {
                PemReader pemReader = new PemReader(reader);
                return (AsymmetricKeyParameter)pemReader.ReadObject();
            }
        }
    }
}
