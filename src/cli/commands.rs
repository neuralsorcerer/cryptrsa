// Copyright Soumyadip Sarkar 2025. All Rights Reserved

use base64::{decode, encode};
use clap::{Parser, Subcommand};
use num_bigint::BigUint;
use std::fs::File;
use std::io::{self, Read, Write};

use crate::crypto::rsa::{
    decrypt, decrypt_bytes_raw, encrypt, encrypt_bytes_raw, sign, sign_hash, verify, verify_hash,
    RSAKeyPair, RSAPublicKey,
};
use crate::crypto::padding::RsaOaep;
use crate::crypto::hybrid::{encrypt_aes_gcm, decrypt_aes_gcm, gen_random_key};

#[derive(Parser)]
#[command(author, version, about)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
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
    EncryptBytes {
        #[arg(short, long)]
        key: String,
        #[arg(long)]
        in_file: String,
        #[arg(long)]
        out_file: String,
    },
    DecryptBytes {
        #[arg(short, long)]
        key: String,
        #[arg(long)]
        in_file: String,
        #[arg(long)]
        out_file: String,
        #[arg(long, default_value_t = false)]
        base64: bool,
    },
    Info {
        #[arg(short, long)]
        key: String,
    },
    Pubout {
        #[arg(short, long)]
        keypair: String,
        #[arg(short, long)]
        out: String,
    },
    GenPem {
        #[arg(short = 'b', long, default_value_t = 2048)]
        bits: usize,
        #[arg(long)]
        private_out: String,
        #[arg(long)]
        public_out: String,
    },
    EncryptOaep {
        #[arg(long)]
        public_pem: String,
        #[arg(long)]
        in_file: String,
        #[arg(long)]
        out_file: String,
    },
    DecryptOaep {
        #[arg(long)]
        private_pem: String,
        #[arg(long)]
        in_file: String,
        #[arg(long)]
        out_file: String,
    },
    SignPss {
        #[arg(long)]
        private_pem: String,
        #[arg(long)]
        in_file: String,
        #[arg(long)]
        sig_out: String,
    },
    VerifyPss {
        #[arg(long)]
        public_pem: String,
        #[arg(long)]
        in_file: String,
        #[arg(long)]
        sig_file: String,
    },
    EncryptHybrid {
        #[arg(long)]
        public_pem: String,
        #[arg(long)]
        in_file: String,
        #[arg(long)]
        out_file: String,
    },
    DecryptHybrid {
        #[arg(long)]
        private_pem: String,
        #[arg(long)]
        in_file: String,
        #[arg(long)]
        out_file: String,
    },
}

pub fn read_input(arg: Option<String>, file: Option<String>) -> io::Result<String> {
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

pub fn write_output(data: &str, out: Option<String>) -> io::Result<()> {
    if let Some(path) = out {
        let mut f = File::create(path)?;
        f.write_all(data.as_bytes())
    } else {
        println!("{}", data);
        Ok(())
    }
}

pub fn load_public_key(path: &str) -> io::Result<RSAPublicKey> {
    if let Ok(kp) = RSAKeyPair::load_from(path) {
        Ok(kp.public_key())
    } else {
        RSAPublicKey::load_from(path)
    }
}

pub fn run(cli: Cli) -> io::Result<()> {
    match cli.command {
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
            let pubkey = load_public_key(&key)?;
            let msg = read_input(message, in_file)?;
            let m = BigUint::from_bytes_be(msg.as_bytes());
            if m >= pubkey.n {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "message is too large for the RSA modulus; use hashing/chunking",
                ));
            }
            let enc = encrypt(&m, &pubkey.e, &pubkey.n);
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
            let bytes = decode(&text).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "Invalid base64"))?;
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
                if m >= keys.n {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "message is too large for the RSA modulus; use --hash",
                    ));
                }
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
            let pubkey = load_public_key(&key)?;
            let msg = read_input(message, message_file)?;
            let sig_text = read_input(signature, signature_file)?;
            let sig_bytes = decode(&sig_text).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "Invalid base64"))?;
            let sig = BigUint::from_bytes_be(&sig_bytes);
            let ok = if hash {
                verify_hash(msg.as_bytes(), &sig, &pubkey.e, &pubkey.n)
            } else {
                let m = BigUint::from_bytes_be(msg.as_bytes());
                verify(&m, &sig, &pubkey.e, &pubkey.n)
            };
            println!("{}", if ok { "valid" } else { "invalid" });
        }
        Commands::Fingerprint { key } => {
            let pubkey = load_public_key(&key)?;
            println!("{}", pubkey.fingerprint());
        }
        Commands::EncryptBytes { key, in_file, out_file } => {
            let pubkey = load_public_key(&key)?;
            let mut data = Vec::new();
            File::open(&in_file)?.read_to_end(&mut data)?;
            let cipher = encrypt_bytes_raw(&data, &pubkey.e, &pubkey.n);
            let b64 = encode(cipher);
            write_output(&b64, Some(out_file))?;
        }
        Commands::DecryptBytes { key, in_file, out_file, base64 } => {
            let keys = RSAKeyPair::load_from(&key)?;
            let mut buf = Vec::new();
            File::open(&in_file)?.read_to_end(&mut buf)?;
            let cipher = if base64 {
                let s = String::from_utf8_lossy(&buf);
                decode(s.trim()).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "Invalid base64"))?
            } else {
                buf
            };
            let plain = decrypt_bytes_raw(&cipher, &keys.d, &keys.n)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "Invalid ciphertext length"))?;
            let mut f = File::create(&out_file)?;
            f.write_all(&plain)?;
        }
        Commands::Info { key } => {
            let pubkey = load_public_key(&key)?;
            let bits = pubkey.n.bits();
            println!("type: RSA");
            println!("bits: {}", bits);
            println!("e: {}", pubkey.e);
            println!("n: {}", hex::encode(pubkey.n.to_bytes_be()));
        }
        Commands::Pubout { keypair, out } => {
            let kp = RSAKeyPair::load_from(&keypair)?;
            kp.public_key().save_to(out)?;
            println!("public key written");
        }
        Commands::GenPem { bits, private_out, public_out } => {
            let kp = RsaOaep::generate(bits).map_err(to_ioe)?;
            std::fs::write(&private_out, kp.private_to_pem().map_err(to_ioe)?)?;
            std::fs::write(&public_out, kp.public_to_pem().map_err(to_ioe)?)?;
            println!("PEM keys written");
        }
        Commands::EncryptOaep { public_pem, in_file, out_file } => {
            let pem = std::fs::read_to_string(&public_pem)?;
            let kp = RsaOaep::from_public_pem(&pem).map_err(to_ioe)?;
            let data = std::fs::read(&in_file)?;
            let ct = kp.encrypt(&data).map_err(to_ioe)?;
            std::fs::write(&out_file, base64::encode(ct))?;
        }
        Commands::DecryptOaep { private_pem, in_file, out_file } => {
            let pem = std::fs::read_to_string(&private_pem)?;
            let kp = RsaOaep::from_private_pem(&pem).map_err(to_ioe)?;
            let b64 = std::fs::read_to_string(&in_file)?;
            let ct = base64::decode(b64.trim()).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "Invalid base64"))?;
            let pt = kp.decrypt(&ct).map_err(to_ioe)?;
            std::fs::write(&out_file, pt)?;
        }
        Commands::SignPss { private_pem, in_file, sig_out } => {
            let pem = std::fs::read_to_string(&private_pem)?;
            let kp = RsaOaep::from_private_pem(&pem).map_err(to_ioe)?;
            let data = std::fs::read(&in_file)?;
            let sig = kp.sign_pss(&data).map_err(to_ioe)?;
            std::fs::write(&sig_out, base64::encode(sig))?;
        }
        Commands::VerifyPss { public_pem, in_file, sig_file } => {
            let pem = std::fs::read_to_string(&public_pem)?;
            let kp = RsaOaep::from_public_pem(&pem).map_err(to_ioe)?;
            let data = std::fs::read(&in_file)?;
            let sig_b64 = std::fs::read_to_string(&sig_file)?;
            let sig = base64::decode(sig_b64.trim()).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "Invalid base64"))?;
            let ok = kp.verify_pss(&data, &sig).map_err(to_ioe)?;
            println!("{}", if ok { "valid" } else { "invalid" });
        }
        Commands::EncryptHybrid { public_pem, in_file, out_file } => {
            let data = std::fs::read(&in_file)?;
            let aes_key = gen_random_key();
            let (ct, nonce) = encrypt_aes_gcm(&aes_key, &data).map_err(to_ioe)?;
            let pem = std::fs::read_to_string(&public_pem)?;
            let kp = RsaOaep::from_public_pem(&pem).map_err(to_ioe)?;
            let enc_key = kp.encrypt(&aes_key).map_err(to_ioe)?;
            let package = serde_json::json!({
                "enc_key": base64::encode(enc_key),
                "nonce": base64::encode(nonce),
                "ct": base64::encode(ct),
            });
            std::fs::write(&out_file, serde_json::to_string_pretty(&package).unwrap())?;
        }
        Commands::DecryptHybrid { private_pem, in_file, out_file } => {
            let pem = std::fs::read_to_string(&private_pem)?;
            let kp = RsaOaep::from_private_pem(&pem).map_err(to_ioe)?;
            let s = std::fs::read_to_string(&in_file)?;
            let v: serde_json::Value = serde_json::from_str(&s).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
            let enc_key = base64::decode(v["enc_key"].as_str().ok_or_else(|| ioerr("missing enc_key"))?.trim()).map_err(|_| ioerr("Invalid base64 enc_key"))?;
            let nonce = base64::decode(v["nonce"].as_str().ok_or_else(|| ioerr("missing nonce"))?.trim()).map_err(|_| ioerr("Invalid base64 nonce"))?;
            let ct = base64::decode(v["ct"].as_str().ok_or_else(|| ioerr("missing ct"))?.trim()).map_err(|_| ioerr("Invalid base64 ct"))?;
            let aes_key = kp.decrypt(&enc_key).map_err(to_ioe)?;
            if aes_key.len() != 32 || nonce.len() != 12 { return Err(ioerr("bad key/nonce size")); }
            let mut key_arr = [0u8;32]; key_arr.copy_from_slice(&aes_key);
            let mut nonce_arr = [0u8;12]; nonce_arr.copy_from_slice(&nonce);
            let pt = decrypt_aes_gcm(&key_arr, &ct, &nonce_arr).map_err(to_ioe)?;
            std::fs::write(&out_file, pt)?;
        }
    }
    Ok(())
}

fn ioerr(msg: &str) -> io::Error { io::Error::new(io::ErrorKind::InvalidInput, msg) }
fn to_ioe<E: std::fmt::Display>(e: E) -> io::Error { io::Error::new(io::ErrorKind::Other, e.to_string()) }
