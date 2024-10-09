using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Security;

namespace BouncyCastle_Cryption
{
    class ChaCha20EncryptionSteam
    {
        // Encrypt using ChaCha20
        public static byte[] Encrypt(byte[] key, byte[] nonce, byte[] data)
        {
            var chacha20 = new ChaChaEngine();
            var keyParameter = new KeyParameter(key);
            chacha20.Init(true, new ParametersWithIV(keyParameter, nonce));

            byte[] output = new byte[data.Length];
            chacha20.ProcessBytes(data, 0, data.Length, output, 0);
            return output;
        }

        // Decrypt using ChaCha20
        public static byte[] Decrypt(byte[] key, byte[] nonce, byte[] data)
        {
            // ChaCha20 is symmetric, so decryption is the same as encryption
            return Encrypt(key, nonce, data);
        }



        // SERVER
        public static void StartServer(int port, byte[] key, byte[] nonce)
        {
            TcpListener listener = new TcpListener(IPAddress.Any, port);
            listener.Start();
            Console.WriteLine("Server started...");

            while (true)
            {
                using (var client = listener.AcceptTcpClient())
                {
                    using (var stream = client.GetStream())
                    {
                        byte[] buffer = new byte[1024];
                        int bytesRead = stream.Read(buffer, 0, buffer.Length);
                        byte[] decryptedData = Decrypt(key, nonce, buffer);
                        Console.WriteLine($"Received: {Encoding.UTF8.GetString(decryptedData, 0, bytesRead)}");
                    }
                }
            }
        }


        // CLIENT
        public static void StartClient(string serverIp, int port, byte[] key, byte[] nonce)
        {
            using (var client = new TcpClient(serverIp, port))
            {
                using (var stream = client.GetStream())
                {
                    string message = "Hello, Server!";
                    byte[] data = Encoding.UTF8.GetBytes(message);
                    byte[] encryptedData = Encrypt(key, nonce, data);
                    stream.Write(encryptedData, 0, encryptedData.Length);
                    Console.WriteLine("Data sent to server.");
                }
            }
        }


        public static void Test()
        {
            byte[] key = new byte[32]; // ChaCha20 key size (256 bits)
            byte[] nonce = new byte[12]; // ChaCha20 nonce size (96 bits)

            // Generate random key and nonce
            var random = new SecureRandom();
            random.NextBytes(key);
            random.NextBytes(nonce);

            // Start server in a separate thread
            var serverThread = new Thread(() => StartServer(12345, key, nonce));
            serverThread.Start();

            // Allow server some time to start
            Thread.Sleep(1000);

            // Start client
            StartClient("127.0.0.1", 12345, key, nonce);
        }
    }
}
