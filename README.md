# RSA Encryption System

This project implements a basic RSA encryption system in Rust. It demonstrates the generation of RSA keys, encrypting and decrypting messages, and ensuring that the encrypted data can be safely converted to and from a string format using base64 encoding.

## Getting Started

These instructions will get you a copy of the project up and running on your local machine.

### Installing

A step-by-step series of examples that tell you how to get a development environment running:

Clone the repository:

```bash
git clone https://github.com/neuralsorcerer/cryptrsa
cd cryptrsa
```

### Build the project

```bash
cargo build
```

### Generating keys

```bash
cargo run -- gen --bits 2048 --out mykeys.json --public-out mypublic.json
```

You can also omit the `--message` flag to be prompted for input.

### Encrypting a message

```bash
cargo run -- encrypt --key mypublic.json --message "hello"
```

### Decrypting a message

```bash
cargo run -- decrypt --key mykeys.json --ciphertext <base64>
```

### Signing a message

```bash
cargo run -- sign --key mykeys.json --message "hello" --hash
```

### Verifying a signature

```bash
cargo run -- verify --key mypublic.json --message "hello" --signature <base64> --hash
```

Commands like `encrypt`, `decrypt`, `sign`, and `verify` also support `--in-file` and `--out-file` to read from or write to a file instead of STDIN or STDOUT.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
