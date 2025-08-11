// Copyright Soumyadip Sarkar 2025. All Rights Reserved

use aes_gcm::{aead::{Aead, KeyInit, OsRng}, Aes256Gcm, Nonce};
use rand::RngCore;

pub fn encrypt_aes_gcm(key: &[u8; 32], plaintext: &[u8]) -> anyhow::Result<(Vec<u8>, [u8;12])> {
    let cipher = Aes256Gcm::new_from_slice(key).expect("key size");
    let mut nonce_bytes = [0u8;12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ct = cipher.encrypt(nonce, plaintext).map_err(|e| anyhow::anyhow!(e))?;
    Ok((ct, nonce_bytes))
}

pub fn decrypt_aes_gcm(key: &[u8; 32], ciphertext: &[u8], nonce: &[u8;12]) -> anyhow::Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key).expect("key size");
    let nonce = Nonce::from_slice(nonce);
    let pt = cipher.decrypt(nonce, ciphertext).map_err(|e| anyhow::anyhow!(e))?;
    Ok(pt)
}

pub fn gen_random_key() -> [u8;32] {
    let mut k = [0u8;32];
    OsRng.fill_bytes(&mut k);
    k
}
