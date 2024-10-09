using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.OpenSsl;
using System;
using System.IO;
using System.Text;

namespace BouncyCastle_Cryption
{
    class VerifySign
    {
        public static void Verify()
        {
            // Load private key from PEM file
            AsymmetricKeyParameter privateKey = LoadPrivateKeyFromPem("private_key.pem");

            // Load public key from PEM file
            AsymmetricKeyParameter publicKey = LoadPublicKeyFromPem("public_key.pem");

            // Sample data to sign
            string dataToSign = "This is the data I want to sign";
            byte[] dataBytes = Encoding.UTF8.GetBytes(dataToSign);

            // Sign the data with the private key
            byte[] signature = SignData(privateKey, dataBytes);

            Console.WriteLine("Data signed successfully");

            // Verify the signature with the public key
            bool isVerified = VerifySignature(publicKey, dataBytes, signature);

            Console.WriteLine($"Signature Verified: {isVerified}");
        }

        // Method to sign data using the private key
        public static byte[] SignData(AsymmetricKeyParameter privateKey, byte[] data)
        {
            ISigner signer = new RsaDigestSigner(new Org.BouncyCastle.Crypto.Digests.Sha256Digest()); // SHA-256 with RSA
            signer.Init(true, privateKey); // true = for signing
            signer.BlockUpdate(data, 0, data.Length);
            return signer.GenerateSignature();
        }

        // Method to verify the signature using the public key
        public static bool VerifySignature(AsymmetricKeyParameter publicKey, byte[] data, byte[] signature)
        {
            ISigner verifier = new RsaDigestSigner(new Org.BouncyCastle.Crypto.Digests.Sha256Digest()); // SHA-256 with RSA
            verifier.Init(false, publicKey); // false = for verifying
            verifier.BlockUpdate(data, 0, data.Length);
            return verifier.VerifySignature(signature);
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
