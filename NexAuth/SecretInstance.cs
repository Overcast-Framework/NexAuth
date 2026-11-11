using System;
using System.Collections.Generic;
using System.Text;

namespace NexAuth
{
    public class SecretInstance
    { 
        public string Issuer { get; set; }
        public string Secret { get; set; }
        public string Account { get; set; }
        public string Algorithm { get; set; }
        public OTPType Type { get; set; }
        public int Digits { get; set; }
        public int Period { get; set; }
    }

    public enum OTPType
    {
        TOTP,
        HOTP
    }
}
