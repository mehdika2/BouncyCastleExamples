using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using System;
using System.Collections.Generic;
using System.Text;

namespace BouncyCastle_Cryption
{
    class Hasher
    {
        public static void Hash(string input)
        {
            byte[] inputBytes = Encoding.UTF8.GetBytes(input);

            // Hash the input with all Bouncy Castle algorithms
            Dictionary<string, byte[]> hashes = HashWithAllAlgorithms(inputBytes);

            // Print out the results
            foreach (var hashEntry in hashes)
            {
                string algorithmName = hashEntry.Key;
                string hashHex = BitConverter.ToString(hashEntry.Value).Replace("-", "");
                Console.WriteLine($"{algorithmName}: {hashHex}");
            }
        }

        public static Dictionary<string, byte[]> HashWithAllAlgorithms(byte[] input)
        {
            // Store results in a dictionary (algorithm name -> hash result)
            var hashResults = new Dictionary<string, byte[]>();

            // List of supported hash algorithms
            var digesters = new Dictionary<string, IDigest>
        {
            { "MD5", new MD5Digest() },
            { "SHA-1", new Sha1Digest() },
            { "SHA-224", new Sha224Digest() },
            { "SHA-256", new Sha256Digest() },
            { "SHA-384", new Sha384Digest() },
            { "SHA-512", new Sha512Digest() },
            { "RIPEMD160", new RipeMD160Digest() },
            { "RIPEMD256", new RipeMD256Digest() },
            { "RIPEMD320", new RipeMD320Digest() },
            { "Tiger", new TigerDigest() },
            { "Whirlpool", new WhirlpoolDigest() }
        };

            // Iterate over each algorithm and compute the hash
            foreach (var entry in digesters)
            {
                string algorithmName = entry.Key;
                IDigest digest = entry.Value;

                byte[] hash = ComputeHash(digest, input);
                hashResults.Add(algorithmName, hash);
            }

            return hashResults;
        }

        // Helper method to compute the hash
        public static byte[] ComputeHash(IDigest digest, byte[] input)
        {
            digest.Reset();
            digest.BlockUpdate(input, 0, input.Length);
            byte[] result = new byte[digest.GetDigestSize()];
            digest.DoFinal(result, 0);
            return result;
        }
    }
}
