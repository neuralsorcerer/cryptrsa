use base64::{decode, encode};
use clap::{Parser, Subcommand};
use num_bigint::BigUint;
use std::fs::File;
use std::io::{self, Read, Write};

use cryptrsa::{decrypt, encrypt, sign, sign_hash, verify, verify_hash, RSAKeyPair, RSAPublicKey};


#[derive(Parser)]
#[command(author, version, about)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Gen {
        #[arg(short = 'b', long, default_value_t = 2048)]
        bits: usize,
        #[arg(short, long, default_value = "keypair.json")]
        out: String,
        #[arg(long)]
        public_out: Option<String>,
    },
    Encrypt {
        #[arg(short, long)]
        key: String,
        #[arg(short, long)]
        message: Option<String>,
        #[arg(long)]
        in_file: Option<String>,
        #[arg(long)]
        out_file: Option<String>,
    },
    Decrypt {
        #[arg(short, long)]
        key: String,
        #[arg(short, long)]
        ciphertext: Option<String>,
        #[arg(long)]
        in_file: Option<String>,
        #[arg(long)]
        out_file: Option<String>,
    },
    Sign {
        #[arg(short, long)]
        key: String,
        #[arg(short, long)]
        message: Option<String>,
        #[arg(long)]
        in_file: Option<String>,
        #[arg(long)]
        out_file: Option<String>,
        #[arg(long)]
        hash: bool,
    },
    Verify {
        #[arg(short, long)]
        key: String,
        #[arg(short, long)]
        message: Option<String>,
        #[arg(short, long)]
        signature: Option<String>,
        #[arg(long)]
        message_file: Option<String>,
        #[arg(long)]
        signature_file: Option<String>,
        #[arg(long)]
        hash: bool,
    },
    Fingerprint {
        #[arg(short, long)]
        key: String,
    },
}

fn read_input(arg: Option<String>, file: Option<String>) -> io::Result<String> {
    if let Some(path) = file {
        let mut buf = String::new();
        File::open(path)?.read_to_string(&mut buf)?;
        Ok(buf.trim_end().to_string())
    } else if let Some(v) = arg {
        Ok(v)
    } else {
        let mut input = String::new();
        io::stdin().read_to_string(&mut input)?;
        Ok(input.trim_end().to_string())
    }
}

fn write_output(data: &str, out: Option<String>) -> io::Result<()> {
    if let Some(path) = out {
        let mut f = File::create(path)?;
        f.write_all(data.as_bytes())
    } else {
        println!("{}", data);
        Ok(())
    }
}

fn load_public_key(path: &str) -> io::Result<RSAPublicKey> {
    if let Ok(kp) = RSAKeyPair::load_from(path) {
        Ok(kp.public_key())
    } else {
        RSAPublicKey::load_from(path)
    }
}


fn main() -> std::io::Result<()> {
    match Cli::parse().command {
        Commands::Gen {
            bits,
            out,
            public_out,
        } => {
            let keys = RSAKeyPair::generate(bits);
            keys.save_to(&out)?;
            if let Some(p) = public_out {
                keys.public_key().save_to(&p)?;
            }
            println!("Key pair saved to {}", out);
        }

        Commands::Encrypt {
            key,
            message,
            in_file,
            out_file,
        } => {
            let keys = RSAKeyPair::load_from(&key)?;
            let msg = read_input(message, in_file)?;
            let m = BigUint::from_bytes_be(msg.as_bytes());
            let enc = encrypt(&m, &keys.e, &keys.n);
            let encoded = encode(enc.to_bytes_be());
            write_output(&encoded, out_file)?;
        }

        Commands::Decrypt {
            key,
            ciphertext,
            in_file,
            out_file,
        } => {
            let keys = RSAKeyPair::load_from(&key)?;
            let text = read_input(ciphertext, in_file)?;
            let bytes = decode(&text).expect("Invalid base64");
            let c = BigUint::from_bytes_be(&bytes);
            let dec = decrypt(&c, &keys.d, &keys.n);
            let msg_bytes = dec.to_bytes_be();
            let out = String::from_utf8_lossy(&msg_bytes);
            write_output(&out, out_file)?;
        }

        Commands::Sign {
            key,
            message,
            in_file,
            out_file,
            hash,
        } => {
            let keys = RSAKeyPair::load_from(&key)?;
            let msg = read_input(message, in_file)?;
            let sig = if hash {
                sign_hash(msg.as_bytes(), &keys.d, &keys.n)
            } else {
                let m = BigUint::from_bytes_be(msg.as_bytes());
                sign(&m, &keys.d, &keys.n)
            };
            let encoded = encode(sig.to_bytes_be());
            write_output(&encoded, out_file)?;
        }

        Commands::Verify {
            key,
            message,
            signature,
            message_file,
            signature_file,
            hash,
        } => {
            let keys = RSAKeyPair::load_from(&key)?;
            let msg = read_input(message, message_file)?;
            let sig_text = read_input(signature, signature_file)?;
            let sig_bytes = decode(&sig_text).expect("Invalid base64");
            let sig = BigUint::from_bytes_be(&sig_bytes);
            let ok = if hash {
                verify_hash(msg.as_bytes(), &sig, &keys.e, &keys.n)
            } else {
                let m = BigUint::from_bytes_be(msg.as_bytes());
                verify(&m, &sig, &keys.e, &keys.n)
            };
            println!("{}", if ok { "valid" } else { "invalid" });
        }

        Commands::Fingerprint { key } => {
            let pubkey = load_public_key(&key)?;
            println!("{}", pubkey.fingerprint());
        }
    }
    Ok(())
}

