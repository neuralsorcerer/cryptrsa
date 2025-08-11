# cryptrsa: RSA CLI and library

A small Rust CLI/library that demonstrates RSA primitives for learning, and provides secure flows using OAEP (encryption), PSS (signing), and a hybrid RSA+AES-GCM scheme for large files.

## Highlights

- Raw RSA primitives (BigUint) for teaching and simple demos
- Chunked raw RSA file encryption with a length header
- RSA-OAEP (SHA-256) encryption/decryption with PEM keys
- RSA-PSS (SHA-256) signing/verification with PEM keys
- Hybrid RSA+AES-256-GCM for large files
- JSON keypair I/O for raw RSA; PEM I/O for OAEP/PSS
- Clean CLI plus a usable library API

## Installation

```bash
cargo install cryptrsa
```

## Build from source

```bash
git clone https://github.com/neuralsorcerer/cryptrsa
cd cryptrsa
cargo build
```

## Quick start (raw RSA, JSON keys)

- Generate JSON keypair:
  ```bash
  cryptrsa gen --bits 2048 --out keypair.json --public-out public.json
  ```
- Encrypt/Decrypt a short UTF-8 message (must be numerically < n):
  ```bash
  cryptrsa encrypt --key public.json --message "hello"

  cryptrsa decrypt --key keypair.json --ciphertext BASE64
  ```
- Encrypt/Decrypt arbitrary files with raw RSA chunking:
  ```bash
  cryptrsa encrypt-bytes --key public.json --in-file input.bin --out-file cipher.b64

  cryptrsa decrypt-bytes --key keypair.json --in-file cipher.b64 --out-file output.bin --base64
  ```
## Secure modes (PEM keys)

- Generate PEM keys (PKCS#8 private, SPKI public):
  ```bash
  cryptrsa gen-pem --bits 2048 --private-out private.pem --public-out public.pem
  ```
- RSA-OAEP (SHA-256) encryption/decryption:
  ```bash
  cryptrsa encrypt-oaep --public-pem public.pem --in-file msg.bin --out-file ct.b64

  cryptrsa decrypt-oaep --private-pem private.pem --in-file ct.b64 --out-file msg.bin
  ```
- RSA-PSS (SHA-256) signing/verification:
  ```bash
  cryptrsa sign-pss --private-pem private.pem --in-file msg.bin --sig-out sig.b64

  cryptrsa verify-pss --public-pem public.pem --in-file msg.bin --sig-file sig.b64
  ```
## Hybrid RSA + AES-GCM (recommended for large files)

- Encrypt: AES-256-GCM for data, RSA-OAEP for the AES key. Output is JSON with base64 fields enc_key, nonce, ct.
  ```bash
  cryptrsa encrypt-hybrid --public-pem public.pem --in-file large.bin --out-file package.json
  ```
- Decrypt:
  ```bash
  cryptrsa decrypt-hybrid --private-pem private.pem --in-file package.json --out-file large.bin
  ```
## CLI reference (subcommands)

- gen: Generate a JSON keypair; optionally write public part separately
- encrypt / decrypt: Raw RSA for short messages (as base64)
- sign / verify: Raw RSA signing; use --hash to sign SHA-256(msg)
- fingerprint: Print SHA-256 fingerprint of a public key (e||n)
- encrypt-bytes / decrypt-bytes: Raw RSA for arbitrary files (chunked); decrypt supports --base64
- info: Print basic info (type, bits, e, n)
- pubout: Extract public key JSON from a keypair JSON
- gen-pem: Generate RSA PEM keys
- encrypt-oaep / decrypt-oaep: RSA-OAEP (SHA-256) with PEM
- sign-pss / verify-pss: RSA-PSS (SHA-256) with PEM
- encrypt-hybrid / decrypt-hybrid: Hybrid RSA-OAEP + AES-256-GCM for large files

## Library usage (examples)

- Raw RSA keygen and encrypt/decrypt:

```rust
use cryptrsa::{RSAKeyPair, encrypt, decrypt};
use num_bigint::BigUint;

let kp = RSAKeyPair::generate(1024);
let m = BigUint::from(42u32);
let c = encrypt(&m, &kp.e, &kp.n);
let p = decrypt(&c, &kp.d, &kp.n);
assert_eq!(m, p);
```

- OAEP/PSS with PEM:

```rust
use cryptrsa::RsaOaep;

let kp = RsaOaep::generate(2048)?;
let ct = kp.encrypt(b"secret")?;
let pt = kp.decrypt(&ct)?;
assert_eq!(pt, b"secret");
let sig = kp.sign_pss(b"msg")?;
assert!(kp.verify_pss(b"msg", &sig)?);
```

- Hybrid AES-GCM:

```rust
use cryptrsa::crypto::hybrid::{gen_random_key, encrypt_aes_gcm, decrypt_aes_gcm};
let key = gen_random_key();
let (ct, nonce) = encrypt_aes_gcm(&key, b"data")?;
let pt = decrypt_aes_gcm(&key, &ct, &nonce)?;
assert_eq!(pt, b"data");
```

## Security notes

- Prefer OAEP/PSS and the hybrid mode for any real use. Raw RSA (no padding) is for learning and is not CCA-secure.
- AES-GCM uses a random 96-bit nonce from the OS RNG; never reuse nonces with the same key.
- Always keep private keys secure; PEM files are written in plaintext by default.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
