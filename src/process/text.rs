use crate::{get_reader, process_genpass, TextEncryptFormat, TextSignFormat};
use anyhow::{anyhow, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chacha20poly1305::aead::generic_array::GenericArray;
use chacha20poly1305::aead::Aead;
use chacha20poly1305::{AeadCore, KeyInit, XChaCha20Poly1305};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use std::fs;
use std::io::Read;
use std::path::Path;

pub trait TextSign {
    /// Sign the data from the reader and return the signature
    fn sign(&self, reader: &mut dyn Read) -> Result<Vec<u8>>;
}

pub trait TextVerify {
    // 静态分派，等价于:
    // fn verify<R: Read>(&self, reader: R, sig: &[u8]) -> Result<bool>
    /// Verify the data from reader with signature
    fn verify(&self, reader: impl Read, sig: &[u8]) -> Result<bool>;
}

pub trait KeyLoader {
    fn load(path: impl AsRef<Path>) -> Result<Self>
    where
        Self: Sized; // Sized 表示类型是固定大小的，它是一个标记trait，内部没有任何方法
}

pub trait KeyGenerator {
    fn generate() -> Result<Vec<Vec<u8>>>;
}

pub trait TextEncryptor {
    fn encrypt(&self, reader: impl Read) -> Result<Vec<u8>>;
}

pub trait TextDecryptor {
    fn decrypt(&self, reader: impl Read) -> Result<Vec<u8>>;
}

pub struct Blake3 {
    key: [u8; 32],
}

pub struct Ed25519Signer {
    key: SigningKey,
}

pub struct Ed25519Verifier {
    key: VerifyingKey,
}

pub fn process_text_sign(input: &str, key: &str, format: TextSignFormat) -> Result<String> {
    let mut reader = get_reader(input)?;
    let signed = match format {
        TextSignFormat::Blake3 => {
            let signer = Blake3::load(key)?;
            signer.sign(&mut reader)?
        }
        TextSignFormat::Ed25519 => {
            let signer = Ed25519Signer::load(key)?;
            signer.sign(&mut reader)?
        }
    };
    let signed = URL_SAFE_NO_PAD.encode(&signed);
    Ok(signed)
}

pub fn process_text_verify(
    input: &str,
    key: &str,
    format: TextSignFormat,
    sig: &str,
) -> Result<bool> {
    let mut reader = get_reader(input)?;
    let sig = URL_SAFE_NO_PAD.decode(sig)?;

    let verified = match format {
        TextSignFormat::Blake3 => {
            let verifier = Blake3::load(key)?;
            verifier.verify(&mut reader, &sig)?
        }
        TextSignFormat::Ed25519 => {
            let verifier = Ed25519Verifier::load(key)?;
            verifier.verify(&mut reader, &sig)?
        }
    };
    Ok(verified)
}

impl TextSign for Blake3 {
    fn sign(&self, reader: &mut dyn Read) -> Result<Vec<u8>> {
        // TODO: improve performance by reading in chunks
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf)?;
        Ok(blake3::keyed_hash(&self.key, &buf).as_bytes().to_vec())
    }
}

impl TextVerify for Blake3 {
    fn verify(&self, mut reader: impl Read, sig: &[u8]) -> Result<bool> {
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf)?;

        let hash = blake3::keyed_hash(&self.key, &buf);
        let hash = hash.as_bytes();

        Ok(hash == sig)
    }
}

impl KeyLoader for Blake3 {
    fn load(path: impl AsRef<Path>) -> Result<Self>
    where
        Self: Sized,
    {
        let key = fs::read(path)?;
        Self::try_new(&key)
    }
}

impl KeyGenerator for Blake3 {
    fn generate() -> Result<Vec<Vec<u8>>> {
        let key = process_genpass(32, true, true, true, true)?;
        let key = key.as_bytes().to_vec();
        Ok(vec![key])
    }
}

impl TextSign for Ed25519Signer {
    fn sign(&self, reader: &mut dyn Read) -> Result<Vec<u8>> {
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf)?;
        let sig = self.key.sign(&buf);
        Ok(sig.to_vec())
    }
}
impl KeyLoader for Ed25519Signer {
    fn load(path: impl AsRef<Path>) -> Result<Self>
    where
        Self: Sized,
    {
        let key = fs::read(path)?;
        Self::try_new(&key)
    }
}

impl KeyGenerator for Ed25519Signer {
    fn generate() -> Result<Vec<Vec<u8>>> {
        let mut csprng = OsRng;
        let sk = SigningKey::generate(&mut csprng);
        let pk = sk.verifying_key().to_bytes().to_vec();
        let sk = sk.as_bytes().to_vec();
        Ok(vec![sk, pk])
    }
}

impl TextVerify for Ed25519Verifier {
    fn verify(&self, mut reader: impl Read, sig: &[u8]) -> Result<bool> {
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf)?;
        let sig = Signature::from_bytes(sig.try_into()?);
        let ret = self.key.verify(&buf, &sig).is_ok();
        Ok(ret)
    }
}

impl KeyLoader for Ed25519Verifier {
    fn load(path: impl AsRef<Path>) -> Result<Self>
    where
        Self: Sized,
    {
        let key = fs::read(path)?;
        Self::try_new(&key)
    }
}

impl Blake3 {
    pub fn new(key: [u8; 32]) -> Self {
        Self { key }
    }
    pub fn try_new(key: &[u8]) -> Result<Self> {
        let key = &key[..32];
        let key = key.try_into()?;
        let signer = Self::new(key);
        Ok(signer)
    }
}

impl Ed25519Signer {
    pub fn new(key: SigningKey) -> Self {
        Self { key }
    }
    pub fn try_new(key: &[u8]) -> Result<Self> {
        let key = SigningKey::from_bytes(key.try_into()?);
        let signer = Self::new(key);
        Ok(signer)
    }
}

impl Ed25519Verifier {
    pub fn new(key: VerifyingKey) -> Self {
        Self { key }
    }
    pub fn try_new(key: &[u8]) -> Result<Self> {
        let key = VerifyingKey::from_bytes(key.try_into()?)?;
        let verifier = Ed25519Verifier::new(key);
        Ok(verifier)
    }
}

pub fn process_text_generate(format: TextSignFormat) -> Result<Vec<Vec<u8>>> {
    match format {
        TextSignFormat::Blake3 => Blake3::generate(),
        TextSignFormat::Ed25519 => Ed25519Signer::generate(),
    }
}

pub struct XChaCha20Poly1305Key {
    key: chacha20poly1305::Key,
}

impl XChaCha20Poly1305Key {
    pub fn new(key: chacha20poly1305::Key) -> Self {
        Self { key }
    }
    pub fn try_new(key: &[u8]) -> Result<Self> {
        let ga = chacha20poly1305::Key::from_slice(key);
        let k = Self::new(*ga as chacha20poly1305::Key);
        Ok(k)
    }
}

impl KeyGenerator for XChaCha20Poly1305Key {
    fn generate() -> Result<Vec<Vec<u8>>> {
        let key = XChaCha20Poly1305::generate_key(&mut OsRng);
        let key = key.to_vec();
        Ok(vec![key])
    }
}

impl KeyLoader for XChaCha20Poly1305Key {
    fn load(path: impl AsRef<Path>) -> Result<Self>
    where
        Self: Sized,
    {
        let key = if path.as_ref().is_file() {
            fs::read(path)?
        } else {
            let s = path.as_ref().to_str().unwrap();
            s.as_bytes().to_vec()
        };
        let key = URL_SAFE_NO_PAD.decode(key)?;
        Self::try_new(&key)
    }
}

impl TextEncryptor for XChaCha20Poly1305Key {
    fn encrypt(&self, mut reader: impl Read) -> Result<Vec<u8>> {
        let cipher = XChaCha20Poly1305::new(&self.key);
        let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);

        let mut input = Vec::new();
        reader.read_to_end(&mut input)?;
        let ciphertext = cipher
            .encrypt(&nonce, input.as_slice())
            .map_err(|e| anyhow!(e.to_string()))?;
        // ChaCha20Poly1305 nonce has 192bit fixed size
        // concat nonce with ciphertext, so that it can be
        // decrypted without explicitly input the nonce
        Ok([nonce.to_vec(), ciphertext].concat())
    }
}

pub fn process_text_encrypt(
    input: &str,
    key: &str,
    format: TextEncryptFormat,
) -> Result<Vec<Vec<u8>>> {
    let mut res: Vec<Vec<u8>> = Vec::new();
    let reader = get_reader(input)?;
    let encrypted = match format {
        TextEncryptFormat::XChaCha20Poly1305 => {
            let encryptor = if key != "-" && !key.is_empty() {
                XChaCha20Poly1305Key::load(key)?
            } else {
                println!("Generate a new key for encrypting");
                let gen = XChaCha20Poly1305Key::generate()?;
                XChaCha20Poly1305Key::try_new(gen[0].as_slice())?
            };
            res.push(encryptor.key.to_vec());
            encryptor.encrypt(reader)?
        }
    };
    res.push(encrypted);
    Ok(res)
}

impl TextDecryptor for XChaCha20Poly1305Key {
    fn decrypt(&self, mut reader: impl Read) -> Result<Vec<u8>> {
        let mut input = Vec::new();
        reader.read_to_end(&mut input)?;
        let input = URL_SAFE_NO_PAD.decode(input)?;
        let (nonce, ciphertext) = input.split_at(24);
        let cipher = XChaCha20Poly1305::new(&self.key);
        let n = GenericArray::from_slice(nonce);
        let decrypted = cipher
            .decrypt(n, ciphertext)
            .map_err(|e| anyhow!(e.to_string()))?;
        Ok(decrypted)
    }
}

pub fn process_text_decrypt(input: &str, key: &str, format: TextEncryptFormat) -> Result<Vec<u8>> {
    let reader = get_reader(input)?;
    let decrypted = match format {
        TextEncryptFormat::XChaCha20Poly1305 => {
            let decryptor = XChaCha20Poly1305Key::load(key)?;
            decryptor.decrypt(reader)?
        }
    };

    Ok(decrypted)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blake3_sign_verify() -> Result<()> {
        let blake3 = Blake3::load("fixtures/blake3.txt")?;
        let data = b"hello!";
        let sig = blake3.sign(&mut &data[..]).unwrap();
        assert!(blake3.verify(&data[..], &sig)?);
        Ok(())
    }

    #[test]
    fn test_ed25519_sign_verify() -> Result<()> {
        let sk = Ed25519Signer::load("fixtures/ed25519.sk")?;
        let pk = Ed25519Verifier::load("fixtures/ed25519.pk")?;

        let data = b"hello!";
        let sig = sk.sign(&mut &data[..])?;
        assert!(pk.verify(&data[..], &sig)?);
        Ok(())
    }

    #[test]
    fn test_load_xchacha20poly1305_key() -> Result<()> {
        let _ = XChaCha20Poly1305Key::load("fixtures/xchacha20poly1305_k.txt")?;
        let _ = XChaCha20Poly1305Key::load("7o_szUy1jWr7WID0pXelySSbOmGl5OxqqMXrMRYbk4U")?;
        Ok(())
    }
    #[test]
    fn test_xchacha20_encrypt_decrypt() -> Result<()> {
        let encrypted = process_text_encrypt(
            "fixtures/blake3.txt",
            "-",
            TextEncryptFormat::XChaCha20Poly1305,
        )?;
        let encrypted: Vec<_> = encrypted
            .iter()
            .map(|v| URL_SAFE_NO_PAD.encode(v))
            .collect();
        fs::write("fixtures/xchacha20poly1305_t.txt", &encrypted[1])?;
        let t = process_text_decrypt(
            "fixtures/xchacha20poly1305_t.txt",
            &encrypted[0],
            TextEncryptFormat::XChaCha20Poly1305,
        )?;
        let orign = fs::read("fixtures/blake3.txt")?;
        assert_eq!(t, orign);
        Ok(())
    }
}
