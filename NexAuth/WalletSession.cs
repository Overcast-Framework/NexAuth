using System;
using System.Collections.Generic;
using System.Text;

namespace NexAuth
{
    public sealed class WalletSession
    {
        public SecureWallet? Wallet { get; private set; }

        public bool IsUnlocked => Wallet is not null;

        public void Unlock(SecureWallet wallet)
            => Wallet = wallet;

        public void Lock()
            => Wallet = null;
    }
}
