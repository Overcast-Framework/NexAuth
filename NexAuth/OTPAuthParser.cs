using System;
using System.Collections.Generic;
using System.Text;

namespace NexAuth
{
    public class OTPAuthParser
    {
        public static OTPAuthData? ParseHOTP(string uri)
        {
            if(uri.StartsWith("otpauth://hotp/"))
            {
                var uriData = new Uri(uri);
                var label = uriData.AbsolutePath;

                var queryData = uriData.Query;
                var parameters = queryData.TrimStart('?')
                    .Split('&')
                    .Select(x => x.Split('=', 2))
                    .ToDictionary(
                        x => Uri.UnescapeDataString(x[0]),
                        x => Uri.UnescapeDataString(x[1])
                    );

                OTPAuthData data = new OTPAuthData();

                data.Label = label.Substring(1);
                data.Secret = parameters["secret"];
                data.Algorithm = parameters.ContainsKey("algorithm") ? parameters["algorithm"] : "SHA1";
                data.Digits = parameters.ContainsKey("digits") ? int.Parse(parameters["digits"]) : 6;
                data.Counter = int.Parse(parameters["counter"]);
                data.TOTP = false;

                return data;
            }
            else
            {
                throw new OTPAuthParserException("Invalid OTPAuth URI format: OTPAuth URIs must begin with 'otpauth://hotp/'.");
            }
        }

        public static OTPAuthData? ParseTOTP(string uri)
        {
            if (uri.StartsWith("otpauth://totp/"))
            {
                var uriData = new Uri(uri);
                var label = uriData.AbsolutePath;

                var queryData = uriData.Query;
                var parameters = queryData.TrimStart('?')
                    .Split('&')
                    .Select(x => x.Split('=', 2))
                    .ToDictionary(
                        x => Uri.UnescapeDataString(x[0]),
                        x => Uri.UnescapeDataString(x[1])
                    );

                OTPAuthData data = new OTPAuthData();

                data.Label = label.Substring(1);
                data.Secret = parameters["secret"];
                data.Algorithm = parameters.ContainsKey("algorithm") ? parameters["algorithm"] : "SHA1";
                data.Digits = parameters.ContainsKey("digits") ? int.Parse(parameters["digits"]) : 6;
                data.Period = parameters.ContainsKey("period") ? int.Parse(parameters["period"]) : 30;
                data.TOTP = true;

                return data;
            }
            else
            {
                throw new OTPAuthParserException("Invalid OTPAuth URI format: OTPAuth URIs must begin with 'otpauth://hotp/'.");
            }
        }
    }

    public class OTPAuthParserException : Exception
    {
        public OTPAuthParserException()
        {
        }

        public OTPAuthParserException(string? message) : base(message)
        {
        }
    }

    public record struct OTPAuthData(string Label, string Secret, int Counter, int Period, string Algorithm, int Digits, bool TOTP)
    {
        public byte[] GetSecretKey()
        {
            return Encodings.Base32.FromBase32String(Secret);
        }
    }
}
