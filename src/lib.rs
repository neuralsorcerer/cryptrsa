use num_bigint::{BigUint, RandBigInt, ToBigInt};
use num_integer::Integer;
use num_traits::{One, Zero};
use rand::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json;
use std::fs::File;
use std::path::Path;

const TEST_ROUNDS: usize = 16;

fn big(n: u32) -> BigUint {
    BigUint::from(n)
}

fn generate_prime(bits: usize) -> BigUint {
    let mut rng = thread_rng();
    loop {
        let mut prime_candidate = rng.gen_biguint(bits as u64);
        // ensure odd
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

    'outer: for _ in 0..k {
        let a = thread_rng().gen_biguint_range(&big(2), &(n - 1u32));
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
    let p = generate_prime(bits / 2);
    let q = generate_prime(bits / 2);
    let n = &p * &q;
    let phi = (&p - 1u32) * (&q - 1u32);
    let e = BigUint::from(65537u32);
    let d = mod_inv(&e, &phi).expect("Modular inverse does not exist.");

    (e, d, n)
}

pub fn encrypt(m: &BigUint, e: &BigUint, n: &BigUint) -> BigUint {
    m.modpow(e, n)
}

pub fn decrypt(c: &BigUint, d: &BigUint, n: &BigUint) -> BigUint {
    c.modpow(d, n)
}

#[derive(Serialize, Deserialize)]
pub struct RSAKeyPair {
    pub e: BigUint,
    pub d: BigUint,
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
        serde_json::from_reader(file)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
    }
}