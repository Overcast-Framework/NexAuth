using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace NexAuth
{
    public class OTPGenerator
    {
        private static byte[] PerformHMAC(byte[] key, ulong counter, string algorithm)
        {
            switch (algorithm)
            {
                case "SHA1":
                    byte[] counterBytes = new byte[8];
                    BinaryPrimitives.WriteUInt64BigEndian(counterBytes, (ulong)counter);

                    return HMACSHA1.HashData(key, counterBytes);
                default:
                    throw new ArgumentException("Invalid algorithm type.");
            }
        }

        public static string GenerateFromURI(OTPAuthData data)
        {
            var secretKey = data.GetSecretKey();

            var counter = data.TOTP ? (ulong)Math.Floor((decimal)DateTimeOffset.Now.ToUnixTimeSeconds() / data.Period) : (ulong)data.Counter;
            var hmac = PerformHMAC(secretKey, counter, data.Algorithm);

            int offset = hmac[^1] & 0x0F;
            var trunc = hmac[offset..(offset + 4)];

            int code = ((trunc[0] << 24) | (trunc[1] << 16) | (trunc[2] << 8) | trunc[3]) & 0x7FFFFFFF;
            int otp = code % 1000000;

            string result = otp.ToString("D"+data.Digits);
            return result;
        }

        public static string GenerateFromSecretInstance(SecretInstance data)
        {
            var secretKey = Encodings.Base32.FromBase32String(data.Secret);

            var counter = data.Type == OTPType.TOTP ? (ulong)Math.Floor((decimal)DateTimeOffset.Now.ToUnixTimeSeconds() / data.Period) : (ulong)data.Period;
            var hmac = PerformHMAC(secretKey, counter, "SHA1"); // fix this for other algos

            int offset = hmac[^1] & 0x0F;
            var trunc = hmac[offset..(offset + 4)];

            int code = ((trunc[0] << 24) | (trunc[1] << 16) | (trunc[2] << 8) | trunc[3]) & 0x7FFFFFFF;
            int otp = code % 1000000;

            string result = otp.ToString("D" + data.Digits);
            return result;
        }

        public static string GenerateFromSecret(string secret)
        {
            var secretKey = Encodings.Base32.FromBase32String(secret);

            var counter = (ulong)Math.Floor((decimal)DateTimeOffset.Now.ToUnixTimeSeconds() / 30);
            var hmac = PerformHMAC(secretKey, counter, "SHA1");

            int offset = hmac[^1] & 0x0F;
            var trunc = hmac[offset..(offset + 4)];

            int code = ((trunc[0] << 24) | (trunc[1] << 16) | (trunc[2] << 8) | trunc[3]) & 0x7FFFFFFF;
            int otp = code % 1000000;

            string result = otp.ToString("D6");

            return result;
        }
    }
}
