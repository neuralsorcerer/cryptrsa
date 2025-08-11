// Copyright Soumyadip Sarkar 2025. All Rights Reserved

use hex;
use num_bigint::{BigUint, RandBigInt, ToBigInt};
use num_integer::Integer;
use num_traits::{One, Zero};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use serde_json;
use std::fs::File;
use std::path::Path;
use sha2::{Digest, Sha256};

const TEST_ROUNDS: usize = 40;

fn big(n: u32) -> BigUint {
    BigUint::from(n)
}

fn generate_prime(bits: usize) -> BigUint {
    let mut rng = OsRng;
    loop {
        let mut prime_candidate = rng.gen_biguint(bits as u64);
        prime_candidate.set_bit(0, true);
        prime_candidate.set_bit((bits - 1) as u64, true);
        if is_prime(&prime_candidate, TEST_ROUNDS) {
            return prime_candidate;
        }
    }
}

fn is_prime(n: &BigUint, k: usize) -> bool {
    if *n == big(2) || *n == big(3) {
        return true;
    }
    if n.is_even() || *n < big(2) {
        return false;
    }

    let mut d = n - 1u32;
    let mut r = 0usize;
    while d.is_even() {
        d >>= 1;
        r += 1;
    }

    let mut rng = OsRng;
    'outer: for _ in 0..k {
        let a = rng.gen_biguint_range(&big(2), &(n - 1u32));
        let mut x = a.modpow(&d, n);
        if x == BigUint::one() || x == n - 1u32 {
            continue;
        }
        for _ in 0..r - 1 {
            x = x.modpow(&big(2), n);
            if x == n - 1u32 {
                continue 'outer;
            }
        }
        return false;
    }
    true
}

pub fn mod_inv(a: &BigUint, m: &BigUint) -> Option<BigUint> {
    use num_bigint::BigInt;
    let mut t = BigInt::zero();
    let mut new_t = BigInt::one();
    let mut r = m.to_bigint().unwrap();
    let mut new_r = a.to_bigint().unwrap();

    while new_r != BigInt::zero() {
        let quotient = &r / &new_r;
        let tmp_t = &t - &quotient * &new_t;
        t = new_t;
        new_t = tmp_t;
        let tmp_r = &r - &quotient * &new_r;
        r = new_r;
        new_r = tmp_r;
    }

    if r != BigInt::one() {
        return None;
    }
    if t < BigInt::zero() {
        t += m.to_bigint().unwrap();
    }
    Some(t.to_biguint().unwrap())
}

pub fn generate_rsa_keys(bits: usize) -> (BigUint, BigUint, BigUint) {
    let e = BigUint::from(65537u32);
    loop {
        let p = generate_prime(bits / 2);
        let mut q = generate_prime(bits / 2);
        while q == p {
            q = generate_prime(bits / 2);
        }
        let n = &p * &q;
        let phi = (&p - 1u32) * (&q - 1u32);

        if e.gcd(&phi) != BigUint::one() {
            continue;
        }
        if let Some(d) = mod_inv(&e, &phi) {
            return (e, d, n);
        }
    }
}

pub fn encrypt(m: &BigUint, e: &BigUint, n: &BigUint) -> BigUint {
    m.modpow(e, n)
}

pub fn decrypt(c: &BigUint, d: &BigUint, n: &BigUint) -> BigUint {
    c.modpow(d, n)
}

pub fn sign(m: &BigUint, d: &BigUint, n: &BigUint) -> BigUint {
    m.modpow(d, n)
}

pub fn verify(m: &BigUint, s: &BigUint, e: &BigUint, n: &BigUint) -> bool {
    m == &s.modpow(e, n)
}

pub fn sign_hash(msg: &[u8], d: &BigUint, n: &BigUint) -> BigUint {
    let digest = Sha256::digest(msg);
    let m = BigUint::from_bytes_be(&digest);
    sign(&m, d, n)
}

pub fn verify_hash(msg: &[u8], sig: &BigUint, e: &BigUint, n: &BigUint) -> bool {
    let digest = Sha256::digest(msg);
    let m = BigUint::from_bytes_be(&digest);
    verify(&m, sig, e, n)
}

pub fn modulus_len(n: &BigUint) -> usize {
    let bits = n.bits();
    ((bits + 7) / 8) as usize
}

pub fn max_plaintext_len(n: &BigUint) -> usize {
    let n_bytes = modulus_len(n);
    n_bytes.saturating_sub(1)
}

pub fn encrypt_bytes_raw(data: &[u8], e: &BigUint, n: &BigUint) -> Vec<u8> {
    let n_bytes = modulus_len(n);
    let p_bytes = max_plaintext_len(n);

    let mut plain = Vec::with_capacity(8 + data.len());
    plain.extend_from_slice(&(data.len() as u64).to_be_bytes());
    plain.extend_from_slice(data);
    let rem = plain.len() % p_bytes;
    if rem != 0 {
        plain.resize(plain.len() + (p_bytes - rem), 0);
    }

    let mut out = Vec::with_capacity((plain.len() / p_bytes) * n_bytes);
    for chunk in plain.chunks(p_bytes) {
        let m = BigUint::from_bytes_be(chunk);
        let c = encrypt(&m, e, n);
        let mut c_bytes = c.to_bytes_be();
        if c_bytes.len() < n_bytes {
            let mut padded = vec![0u8; n_bytes - c_bytes.len()];
            padded.extend_from_slice(&c_bytes);
            c_bytes = padded;
        }
        out.extend_from_slice(&c_bytes);
    }
    out
}

pub fn decrypt_bytes_raw(cipher: &[u8], d: &BigUint, n: &BigUint) -> Option<Vec<u8>> {
    let n_bytes = modulus_len(n);
    let p_bytes = max_plaintext_len(n);
    if cipher.len() % n_bytes != 0 {
        return None;
    }
    let mut plain = Vec::with_capacity((cipher.len() / n_bytes) * p_bytes);
    for block in cipher.chunks(n_bytes) {
        let c = BigUint::from_bytes_be(block);
        let m = decrypt(&c, d, n);
        let mut m_bytes = m.to_bytes_be();
        if m_bytes.len() < p_bytes {
            let mut padded = vec![0u8; p_bytes - m_bytes.len()];
            padded.extend_from_slice(&m_bytes);
            m_bytes = padded;
        }
        plain.extend_from_slice(&m_bytes);
    }
    if plain.len() < 8 {
        return None;
    }
    let mut len_bytes = [0u8; 8];
    len_bytes.copy_from_slice(&plain[..8]);
    let total_len = u64::from_be_bytes(len_bytes) as usize;
    if total_len > plain.len().saturating_sub(8) {
        return None;
    }
    Some(plain[8..8 + total_len].to_vec())
}

#[derive(Serialize, Deserialize)]
pub struct RSAKeyPair {
    pub e: BigUint,
    pub d: BigUint,
    pub n: BigUint,
}

#[derive(Serialize, Deserialize)]
pub struct RSAPublicKey {
    pub e: BigUint,
    pub n: BigUint,
}

impl RSAKeyPair {
    pub fn generate(bits: usize) -> Self {
        let (e, d, n) = generate_rsa_keys(bits);
        Self { e, d, n }
    }

    pub fn save_to<P: AsRef<Path>>(&self, path: P) -> std::io::Result<()> {
        let file = File::create(path)?;
        serde_json::to_writer_pretty(file, self)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
    }

    pub fn load_from<P: AsRef<Path>>(path: P) -> std::io::Result<Self> {
        let file = File::open(path)?;
        serde_json::from_reader(file).map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
    }

    pub fn public_key(&self) -> RSAPublicKey {
        RSAPublicKey {
            e: self.e.clone(),
            n: self.n.clone(),
        }
    }
}

impl RSAPublicKey {
    pub fn save_to<P: AsRef<Path>>(&self, path: P) -> std::io::Result<()> {
        let file = File::create(path)?;
        serde_json::to_writer_pretty(file, self)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
    }
    pub fn load_from<P: AsRef<Path>>(path: P) -> std::io::Result<Self> {
        let file = File::open(path)?;
        serde_json::from_reader(file).map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
    }

    pub fn fingerprint(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.e.to_bytes_be());
        hasher.update(self.n.to_bytes_be());
        let digest = hasher.finalize();
        hex::encode(digest)
    }
}
