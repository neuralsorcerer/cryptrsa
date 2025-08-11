// Copyright Soumyadip Sarkar 2025. All Rights Reserved

pub mod crypto;
pub mod cli;

pub use crate::crypto::rsa::{
    decrypt, decrypt_bytes_raw, encrypt, encrypt_bytes_raw, generate_rsa_keys, max_plaintext_len,
    mod_inv, modulus_len, sign, sign_hash, verify, verify_hash, RSAKeyPair, RSAPublicKey,
};

pub use crate::crypto::padding::RsaOaep;