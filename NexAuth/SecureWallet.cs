using Konscious.Security.Cryptography;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace NexAuth
{
    public class SecureWallet
    {
        private byte[] _key { get; set; }
        private byte[] _salt { get; set; }    

        private List<SecretInstance> _secrets = new();

        public void AddSecret(SecretInstance instance)
        {
            _secrets.Add(instance);
        }

        public async Task SaveAsync()
        {
            KDFData kdfData = new KDFData();
            kdfData.Salt = Convert.ToBase64String(_salt);

            var plainTextBytes = JsonSerializer.SerializeToUtf8Bytes(_secrets);

            EncryptedData data = new EncryptedData();
            using AesGcm aesGCM = new AesGcm(_key, 16);

            byte[] nonce = RandomNumberGenerator.GetBytes(12);
            byte[] tag = new byte[16];
            byte[] ciphertext = new byte[plainTextBytes.Length];

            aesGCM.Encrypt(nonce, plainTextBytes, ciphertext, tag);

            data.Nonce = Convert.ToBase64String(nonce);
            data.Tag = Convert.ToBase64String(tag);
            data.Ciphertext = Convert.ToBase64String(ciphertext);

            SecureWalletData serializedData = new SecureWalletData();

            serializedData.Version = 1;
            serializedData.Data = data;
            serializedData.KDF = kdfData;

            await using var walletFileStream = new FileStream(
                "wallet.json.tmp",
                FileMode.Create,
                FileAccess.Write,
                FileShare.None);

            await JsonSerializer.SerializeAsync(walletFileStream, serializedData);
            await walletFileStream.FlushAsync();
            walletFileStream.Close();

            File.Move("wallet.json.tmp", "wallet.json", true);
        }

        public static async Task<SecureWallet> CreateWalletAsync(string pin)
        {
            SecureWallet wallet = new SecureWallet();

            Stopwatch sw = Stopwatch.StartNew();
            byte[] salt = RandomNumberGenerator.GetBytes(16);
            
            var arg2 = new Argon2id(Encoding.UTF8.GetBytes(pin));

            arg2.Salt = salt;
            arg2.MemorySize = 128 * 1024; // 128MiB
            arg2.Iterations = 4;
            arg2.DegreeOfParallelism = 1;

            var kdf = await arg2.GetBytesAsync(32);

            wallet._key = kdf;
            wallet._salt = salt;

            sw.Stop();

            Console.WriteLine("KDF took " + sw.ElapsedMilliseconds + " ms.");
            KDFData kdfData = new KDFData();
            kdfData.Salt = Convert.ToBase64String(salt);

            var plainTextBytes = JsonSerializer.SerializeToUtf8Bytes(wallet._secrets);

            EncryptedData data = new EncryptedData();
            using AesGcm aesGCM = new AesGcm(kdf, 16);

            byte[] nonce = RandomNumberGenerator.GetBytes(12);
            byte[] tag = new byte[16];
            byte[] ciphertext = new byte[plainTextBytes.Length];

            aesGCM.Encrypt(nonce, plainTextBytes, ciphertext, tag);

            data.Nonce = Convert.ToBase64String(nonce);
            data.Tag = Convert.ToBase64String(tag);
            data.Ciphertext = Convert.ToBase64String(ciphertext);

            SecureWalletData serializedData = new SecureWalletData();

            serializedData.Version = 1;
            serializedData.Data = data;
            serializedData.KDF = kdfData;

            await using var walletFileStream = File.CreateText("wallet.json");
            await JsonSerializer.SerializeAsync(walletFileStream.BaseStream, serializedData);

            await walletFileStream.FlushAsync();
            walletFileStream.Close();

            return wallet;
        }

        public static UnlockFailureCode TryUnlock(string pin, out SecureWallet? wallet)
        {
            if(File.Exists("wallet.json"))
            {
                SecureWalletData? dsData = JsonSerializer.Deserialize<SecureWalletData>(File.ReadAllText("wallet.json"));
                if (dsData != null)
                {
                    var salt = Convert.FromBase64String(dsData.KDF.Salt);

                    var arg2 = new Argon2id(Encoding.UTF8.GetBytes(pin));

                    arg2.Salt = salt;
                    arg2.MemorySize = 128 * 1024; // 128MiB
                    arg2.Iterations = 4;
                    arg2.DegreeOfParallelism = 1;

                    var kdf = arg2.GetBytes(32);

                    byte[] nonce = Convert.FromBase64String(dsData.Data.Nonce);
                    byte[] tag = Convert.FromBase64String(dsData.Data.Tag);
                    byte[] ciphertext = Convert.FromBase64String(dsData.Data.Ciphertext);

                    byte[] plaintext = new byte[ciphertext.Length];

                    try
                    {
                        using AesGcm aesGCM = new AesGcm(kdf, 16);
                        aesGCM.Decrypt(nonce, ciphertext, tag, plaintext);

                        List<SecretInstance>? secrets = JsonSerializer.Deserialize<List<SecretInstance>>(plaintext);
                        if(secrets != null)
                        {
                            wallet = new SecureWallet();
                            wallet._secrets = secrets;
                            wallet._key = kdf;
                            wallet._salt = salt;

                            return UnlockFailureCode.Success;
                        }
                    }
                    catch(CryptographicException ex)
                    {
                        Console.WriteLine(ex.Message);

                        wallet = null;
                        return UnlockFailureCode.IncorrectPIN;
                    }
                }
            }
                
            wallet = null;
            return UnlockFailureCode.WalletDoesNotExist;
        }

        public IReadOnlyList<SecretInstance> GetSecrets()
        {
            return _secrets.AsReadOnly();
        }
    }

    public enum UnlockFailureCode
    {
        Success,
        WalletDoesNotExist,
        IncorrectPIN
    }

    public class SecureWalletData
    {
        public int Version { get; set; }
        public EncryptedData Data { get; set; }
        public KDFData KDF { get; set; }
    }

    public class KDFData
    {
        public string Salt { get; set; }
    }

    public class EncryptedData
    {
        public string Nonce { get; set; }
        public string Tag { get; set; }
        public string Ciphertext { get; set; }
    }
}
