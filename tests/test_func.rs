// Copyright Soumyadip Sarkar 2025. All Rights Reserved


use cryptrsa::{decrypt, encrypt, sign, sign_hash, verify, verify_hash, RSAKeyPair};
use cryptrsa::crypto::hybrid::{encrypt_aes_gcm, decrypt_aes_gcm, gen_random_key};
use cryptrsa::RsaOaep;
use num_bigint::ToBigUint;
use proptest::prelude::*;


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

#[test]
fn encrypt_decrypt_bytes_chunked() {
    let keys = RSAKeyPair::generate(512);
    let mut data = Vec::with_capacity(5000);
    for i in 0..5000 { data.push((i % 256) as u8); }
    let cipher = cryptrsa::encrypt_bytes_raw(&data, &keys.e, &keys.n);
    let plain = cryptrsa::decrypt_bytes_raw(&cipher, &keys.d, &keys.n).expect("valid cipher");
    assert_eq!(plain, data);
}


#[test]
fn oaep_roundtrip_var_sizes() {
    let kp = RsaOaep::generate(1024).unwrap();
    for size in [0usize, 1, 16, 32, 60] {
        let data: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
        let ct = kp.encrypt(&data).unwrap();
        let pt = kp.decrypt(&ct).unwrap();
        assert_eq!(pt, data, "size {} roundtrip", size);
    }
}

#[test]
fn oaep_decrypt_with_wrong_key_fails() {
    let kp1 = RsaOaep::generate(1024).unwrap();
    let kp2 = RsaOaep::generate(1024).unwrap();
    let data = b"secret";
    let ct = kp1.encrypt(data).unwrap();
    let dec = kp2.decrypt(&ct);
    assert!(dec.is_err(), "decrypt with wrong key should error");
}

#[test]
fn pss_sign_verify_negative_wrong_message() {
    let kp = RsaOaep::generate(1024).unwrap();
    let msg = b"important";
    let sig = kp.sign_pss(msg).unwrap();
    let ok = kp.verify_pss(b"tampered", &sig).unwrap();
    assert!(!ok, "verify on wrong message should fail");
}

#[test]
fn hybrid_roundtrip_var_sizes() {
    let key = gen_random_key();
    for size in [0usize, 1, 16, 1000, 4096] {
        let data: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
        let (ct, nonce) = encrypt_aes_gcm(&key, &data).unwrap();
        let pt = decrypt_aes_gcm(&key, &ct, &nonce).unwrap();
        assert_eq!(pt, data, "size {} roundtrip", size);
    }
}

#[test]
fn hybrid_negative_wrong_nonce() {
    let key = gen_random_key();
    let data = b"hello gcm";
    let (ct, mut nonce) = encrypt_aes_gcm(&key, data).unwrap();
    nonce[0] ^= 0x01;
    let dec = decrypt_aes_gcm(&key, &ct, &nonce);
    assert!(dec.is_err(), "decrypt with wrong nonce should error");
}


proptest! {
    #![proptest_config(ProptestConfig {
        failure_persistence: None,
        cases: 32,
        .. ProptestConfig::default()
    })]

    #[test]
    fn prop_aes_gcm_roundtrip(data in proptest::collection::vec(any::<u8>(), 0..1024)) {
        let key = gen_random_key();
        let (ct, nonce) = encrypt_aes_gcm(&key, &data).unwrap();
        let pt = decrypt_aes_gcm(&key, &ct, &nonce).unwrap();
        prop_assert_eq!(pt, data);
    }
}
