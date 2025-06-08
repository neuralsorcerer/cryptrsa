use base64::{decode, encode};
use clap::{Parser, Subcommand};
use num_bigint::BigUint;

use cryptrsa::{decrypt, encrypt, RSAKeyPair};


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
    },
    Encrypt {
        #[arg(short, long)]
        key: String,
        #[arg(short, long)]
        message: String,
    },
    Decrypt {
        #[arg(short, long)]
        key: String,
        #[arg(short, long)]
        ciphertext: String,
    },
}


fn main() -> std::io::Result<()> {
    match Cli::parse().command {
        Commands::Gen { bits, out } => {
            let keys = RSAKeyPair::generate(bits);
            keys.save_to(&out)?;
            println!("Key pair saved to {}", out);
        }

        Commands::Encrypt { key, message } => {
            let keys = RSAKeyPair::load_from(&key)?;
            let m = BigUint::from_bytes_be(message.as_bytes());
            let enc = encrypt(&m, &keys.e, &keys.n);
            let encoded = encode(enc.to_bytes_be());
            println!("{}", encoded);
        }

        Commands::Decrypt { key, ciphertext } => {
            let keys = RSAKeyPair::load_from(&key)?;
            let bytes = decode(&ciphertext).expect("Invalid base64");
            let c = BigUint::from_bytes_be(&bytes);
            let dec = decrypt(&c, &keys.d, &keys.n);
            let msg_bytes = dec.to_bytes_be();
            let out = String::from_utf8_lossy(&msg_bytes);
            println!("{}", out);
        }
    }
    Ok(())
}

