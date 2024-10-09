using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using System;
using System.IO;

namespace BouncyCastle_Cryption
{
    class KeyGenerator
    {
        public static void GenerateKeyPair(int size)
        {
            RsaKeyPairGenerator keyGen = new RsaKeyPairGenerator();
            KeyGenerationParameters keyGenParam = new KeyGenerationParameters(new SecureRandom(), size);
            keyGen.Init(keyGenParam);

            // Generate key pair
            AsymmetricCipherKeyPair keyPair = keyGen.GenerateKeyPair();

            // Extract the private and public keys
            RsaPrivateCrtKeyParameters privateKey = (RsaPrivateCrtKeyParameters)keyPair.Private;
            RsaKeyParameters publicKey = (RsaKeyParameters)keyPair.Public;

            // Step 2: Save Private Key in PEM format
            using (TextWriter privateKeyTextWriter = new StreamWriter("private_key.pem"))
            {
                PemWriter pemWriter = new PemWriter(privateKeyTextWriter);
                pemWriter.WriteObject(privateKey);
                pemWriter.Writer.Flush();
            }
            Console.WriteLine("Private key saved as private_key.pem");

            // Step 3: Save Public Key in PEM format
            using (TextWriter publicKeyTextWriter = new StreamWriter("public_key.pem"))
            {
                PemWriter pemWriter = new PemWriter(publicKeyTextWriter);
                pemWriter.WriteObject(publicKey);
                pemWriter.Writer.Flush();
            }
            Console.WriteLine("Public key saved as public_key.pem");
        }
    }
}
