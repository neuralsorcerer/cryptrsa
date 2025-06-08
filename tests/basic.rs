use cryptrsa::{decrypt, encrypt, RSAKeyPair};
use num_bigint::ToBigUint;

#[test]
fn encrypt_decrypt_cycle() {
    let keys = RSAKeyPair::generate(512);
    let msg = 42u32.to_biguint().unwrap();
    let enc = encrypt(&msg, &keys.e, &keys.n);
    let dec = decrypt(&enc, &keys.d, &keys.n);
    assert_eq!(msg, dec);
}