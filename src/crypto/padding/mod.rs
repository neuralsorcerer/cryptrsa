// Copyright Soumyadip Sarkar 2025. All Rights Reserved

use rand::rngs::OsRng;
use rsa::{Oaep, RsaPrivateKey, RsaPublicKey};
use pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey, LineEnding};
use sha2::Sha256;

pub struct RsaOaep {
    pub public: RsaPublicKey,
    pub private: Option<RsaPrivateKey>,
}

impl RsaOaep {
    pub fn from_public_pem(pem: &str) -> anyhow::Result<Self> {
        let public = RsaPublicKey::from_public_key_pem(pem)?;
        Ok(Self { public, private: None })
    }
    pub fn from_private_pem(pem: &str) -> anyhow::Result<Self> {
        let private = RsaPrivateKey::from_pkcs8_pem(pem)?;
        let public: RsaPublicKey = private.to_public_key();
        Ok(Self { public, private: Some(private) })
    }
    pub fn public_to_pem(&self) -> anyhow::Result<String> {
        Ok(self.public.to_public_key_pem(LineEnding::LF)?)
    }
    pub fn private_to_pem(&self) -> anyhow::Result<String> {
        match &self.private {
            Some(k) => Ok(k.to_pkcs8_pem(LineEnding::LF)?.to_string()),
            None => anyhow::bail!("no private key available"),
        }
    }

    pub fn generate(bits: usize) -> anyhow::Result<Self> {
        let mut rng = OsRng;
        let private = RsaPrivateKey::new(&mut rng, bits)?;
        let public = RsaPublicKey::from(&private);
        Ok(Self { public, private: Some(private) })
    }

    pub fn encrypt(&self, data: &[u8]) -> anyhow::Result<Vec<u8>> {
        let mut rng = OsRng;
        let enc = self.public.encrypt(&mut rng, Oaep::new::<Sha256>(), data)?;
        Ok(enc)
    }

    pub fn decrypt(&self, cipher: &[u8]) -> anyhow::Result<Vec<u8>> {
        let privk = self.private.as_ref().ok_or_else(|| anyhow::anyhow!("no private key available"))?;
        let dec = privk.decrypt(Oaep::new::<Sha256>(), cipher)?;
        Ok(dec)
    }

    pub fn sign_pss(&self, data: &[u8]) -> anyhow::Result<Vec<u8>> {
        use rsa::pss::BlindedSigningKey;
        use rsa::signature::{RandomizedSigner, SignatureEncoding};
        let privk = self.private.as_ref().ok_or_else(|| anyhow::anyhow!("no private key available"))?;
        let signing_key = BlindedSigningKey::<Sha256>::new(privk.clone());
        let mut rng = OsRng;
        let sig = signing_key.sign_with_rng(&mut rng, data);
        Ok(sig.to_vec())
    }

    pub fn verify_pss(&self, data: &[u8], signature: &[u8]) -> anyhow::Result<bool> {
        use rsa::pss::VerifyingKey;
        use rsa::signature::Verifier;
        let verifying_key = VerifyingKey::<Sha256>::new(self.public.clone());
        let sig = rsa::pss::Signature::try_from(signature)?;
        Ok(verifying_key.verify(data, &sig).is_ok())
    }
}
