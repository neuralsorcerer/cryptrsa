use cryptrsa::{decrypt, encrypt, sign, sign_hash, verify, verify_hash, RSAKeyPair};
use num_bigint::ToBigUint;

#[test]
fn encrypt_decrypt_cycle() {
    let keys = RSAKeyPair::generate(512);
    let msg = 42u32.to_biguint().unwrap();
    let enc = encrypt(&msg, &keys.e, &keys.n);
    let dec = decrypt(&enc, &keys.d, &keys.n);
    assert_eq!(msg, dec);
}

#[test]
fn sign_verify_cycle() {
    let keys = RSAKeyPair::generate(512);
    let msg = 123u32.to_biguint().unwrap();
    let sig = sign(&msg, &keys.d, &keys.n);
    assert!(verify(&msg, &sig, &keys.e, &keys.n));
}

#[test]
fn sign_verify_hash_cycle() {
    let keys = RSAKeyPair::generate(512);
    let msg = b"hash me";
    let sig = sign_hash(msg, &keys.d, &keys.n);
    assert!(verify_hash(msg, &sig, &keys.e, &keys.n));
}

#[test]
fn public_key_roundtrip() {
    let keys = RSAKeyPair::generate(512);
    let public = keys.public_key();
    let msg = 7u32.to_biguint().unwrap();
    let enc = encrypt(&msg, &public.e, &public.n);
    let dec = decrypt(&enc, &keys.d, &keys.n);
    assert_eq!(msg, dec);
}

#[test]
fn fingerprint_length() {
    let keys = RSAKeyPair::generate(512);
    let public = keys.public_key();
    let fp = public.fingerprint();
    assert_eq!(fp.len(), 64);
}