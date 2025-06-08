# RSA Encryption System

This project implements a basic RSA encryption system in Rust. It demonstrates the generation of RSA keys, encrypting and decrypting messages, and ensuring that the encrypted data can be safely converted to and from a string format using base64 encoding.

## Getting Started

Install the CLI directly from [crates.io](https://crates.io/crates/cryptrsa):

```bash
cargo install cryptrsa
```

### Build the project

You can also build from source by cloning the repository:

```bash
git clone https://github.com/neuralsorcerer/cryptrsa
cd cryptrsa
cargo build
```

### Generating keys

```bash
cryptrsa gen --bits 2048 --out mykeys.json --public-out mypublic.json
```

You can also omit the `--message` flag to be prompted for input.

### Encrypting a message

```bash
cryptrsa encrypt --key mypublic.json --message "hello"
```

### Decrypting a message

```bash
cryptrsa decrypt --key mykeys.json --ciphertext <base64>
```

### Signing a message

```bash
cryptrsa sign --key mykeys.json --message "hello" --hash
```

### Verifying a signature

```bash
cryptrsa verify --key mypublic.json --message "hello" --signature <base64> --hash
```

Commands like `encrypt`, `decrypt`, `sign`, and `verify` also support `--in-file` and `--out-file` to read from or write to a file instead of STDIN or STDOUT.

### Computing a public key fingerprint

```bash
cryptrsa fingerprint --key mypublic.json
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
