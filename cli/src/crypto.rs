use crate::Result;
use aes_gcm::{
    aead::{Aead, Generate, Payload},
    Aes256Gcm, KeyInit, Nonce,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use rand::rngs::OsRng;
use rsa::{
    pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey},
    Oaep, RsaPrivateKey, RsaPublicKey,
};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

pub fn context(parts: serde_json::Value) -> String {
    let mut all = vec![serde_json::json!("voe"), serde_json::json!(1)];
    all.extend(parts.as_array().expect("context parts").iter().cloned());
    serde_json::to_string(&all).expect("context serialization")
}
pub fn seal(key: &[u8], value: &[u8], aad: &str) -> Result<String> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| "Invalid encryption key")?;
    let nonce = Nonce::generate();
    let ciphertext = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: value,
                aad: aad.as_bytes(),
            },
        )
        .map_err(|_| "Encryption failed")?;
    let mut data = nonce.to_vec();
    data.extend(ciphertext);
    Ok(format!("v1.{}", STANDARD.encode(data)))
}
pub fn unseal(key: &[u8], envelope: &str, aad: &str) -> Result<Zeroizing<Vec<u8>>> {
    let data = STANDARD.decode(
        envelope
            .strip_prefix("v1.")
            .ok_or("Unsupported encryption format")?,
    )?;
    if data.len() < 28 {
        return Err("Invalid ciphertext".into());
    }
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| "Invalid encryption key")?;
    let value = cipher
        .decrypt(
            (&data[..12]).try_into()?,
            Payload {
                msg: &data[12..],
                aad: aad.as_bytes(),
            },
        )
        .map_err(|_| "Ciphertext authentication failed")?;
    Ok(Zeroizing::new(value))
}
pub fn generate_identity() -> Result<(String, Zeroizing<String>)> {
    let private = RsaPrivateKey::new(&mut OsRng, 3072)?;
    let public = RsaPublicKey::from(&private);
    Ok((
        STANDARD.encode(public.to_public_key_der()?.as_bytes()),
        Zeroizing::new(STANDARD.encode(private.to_pkcs8_der()?.as_bytes())),
    ))
}
pub fn fingerprint(public: &str) -> Result<String> {
    Ok(format!("{:x}", Sha256::digest(STANDARD.decode(public)?)))
}
pub fn unwrap(private: &str, envelope: &str, aad: &str) -> Result<Zeroizing<Vec<u8>>> {
    let private_bytes = Zeroizing::new(STANDARD.decode(private)?);
    let key = RsaPrivateKey::from_pkcs8_der(&private_bytes)?;
    let ciphertext = STANDARD.decode(
        envelope
            .strip_prefix("rsa1.")
            .ok_or("Unsupported key envelope")?,
    )?;
    Ok(Zeroizing::new(key.decrypt_blinded(
        &mut OsRng,
        Oaep::new_with_label::<Sha256, _>(aad),
        &ciphertext,
    )?))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn browser_vectors_decrypt_in_rust() {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../../web/test/fixtures/vault-v1.json")).unwrap();
        let field = |name: &str| fixture[name].as_str().unwrap();
        let key = STANDARD.decode(field("key")).unwrap();
        assert_eq!(
            &*unseal(&key, field("ciphertext"), field("aad")).unwrap(),
            field("plaintext").as_bytes()
        );
        assert_eq!(
            &*unwrap(field("privateKey"), field("wrappedKey"), field("rsaAad")).unwrap(),
            &key
        );
        assert!(unwrap(field("privateKey"), field("wrappedKey"), "wrong recipient").is_err());
    }
    #[test]
    fn aad_and_tampering_are_authenticated() {
        let key = [7u8; 32];
        let value = seal(&key, b"secret", "one").unwrap();
        assert_eq!(&*unseal(&key, &value, "one").unwrap(), b"secret");
        assert!(unseal(&key, &value, "two").is_err());
        assert!(unseal(&[8u8; 32], &value, "one").is_err());
    }
    #[test]
    fn rejects_short_ciphertext() {
        assert!(unseal(&[0; 32], "v1.YQ==", "x").is_err());
    }
}
