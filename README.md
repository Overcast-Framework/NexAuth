# NexAuth



NexAuth is a locally-running cryptographically-locked account-based TOTP authenticator token generator. You can run it in the browser or as a desktop app, with mobile support coming in the future.



## **Technologies**



* C#
* ASP.NET
* Argon2id
* AES-GCM
* .NET MAUI
* tailwindcss(with DaisyUI)



## **Features**



* Password-protected accounts with encrypted TOTP secrets
* Locally stored, encrypted wallets
* Desktop and browser-ready
* Can generate TOTP codes from URIs
* Sleek, modern dark-mode design



## Acknowledgements



NexAuth uses Argon2id for key derivation and NexAuth uses AES‑GCM for authenticated encryption of wallet contents.



NexAuth's security depends on how strong your password is, how NexAuth is implemented, and how safe the environment where NexAuth runs is.



No security system can guarantee protection. Use a unique password and keep your wallet files private. Always keep a backup of your wallet.



NexAuth's security parameters:

* Argon2id with 128 MiB memory cost.
* AES-256-GCM.
* Random 16-byte salts.
* 12-byte nonces and 16-byte authentication tags.

