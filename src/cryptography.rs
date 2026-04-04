use aes_gcm::aead::{self, Aead};
use aes_gcm::{KeyInit, KeySizeUser};
use ml_kem::{EncodedSizeUser, KemCore};
use ml_kem::kem::{Encapsulate, Decapsulate};
use rand::rand_core::UnwrapErr;
use typenum::marker_traits::Unsigned;
use rand_chacha::rand_core::SeedableRng;
// this is the 0.6.4 version, vs the 0.10.0 version from the rand crate
use rand_chacha::rand_core::RngCore as OldRngCore;
use rand_chacha::rand_core::CryptoRng as OldCryptoRng; 

use super::*;

pub type CryptoRng = rand_chacha::ChaCha20Rng;
pub type SysRng = UnwrapErr<rand::rngs::SysRng>;
pub type OldSysRng = rand_chacha::rand_core::OsRng;

type KemParams = ml_kem::MlKem1024Params;
type Kem = ml_kem::kem::Kem<KemParams>;
type RawEncapsulationKey = ml_kem::kem::EncapsulationKey<KemParams>;
type RawDecapsulationKey = ml_kem::kem::DecapsulationKey<KemParams>;
type RawCiphertext = ml_kem::Ciphertext<Kem>;
type RawSharedKey = ml_kem::SharedKey<Kem>;
pub const KEM_KEY_SIZE: usize = 24;

type RawAead = aes_gcm::Aes256Gcm;
type RawAeadKey = aes_gcm::Key<RawAead>;
type RawAeadNonce = [u8; 12];

pub fn get_crypto_rng() -> CryptoRng {rand_chacha::ChaCha20Rng::from_rng(get_old_sys_rng()).unwrap()} 
pub const fn get_sys_rng() -> SysRng {UnwrapErr(rand::rngs::SysRng)}
pub const fn get_old_sys_rng() -> OldSysRng {rand_chacha::rand_core::OsRng}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct AeadKey {
    key: RawAeadKey,
    nonce_rng: CryptoRng,
}

impl AeadKey {
    pub fn new_random(mut rng: impl rand::CryptoRng) -> Self {
        let mut seed= [0u8; 32];
        rng.fill_bytes(&mut seed);
        let mut rng = CryptoRng::from_seed(seed); // getting an rng Aead is happy working with (from rand 0.6.4, not 0.10.0)

        let key = RawAead::generate_key(&mut rng);
        let mut nonce_seed= [0u8; 32];
        rng.fill_bytes(&mut nonce_seed);
        let mut nonce_rng = CryptoRng::from_seed(seed);
        let mut nonce_rng_start: [u8; 16] = [0; _];
        rng.fill_bytes(&mut nonce_rng_start);
        let nonce_rng_start = u128::from_ne_bytes(nonce_rng_start);
        nonce_rng.set_word_pos(nonce_rng_start);
        nonce_rng.set_stream(rng.next_u64());
        Self { key, nonce_rng }
    }

    pub fn encrypt(&mut self, to_encrypt: &[u8], associated: &[u8]) -> Result<(u128, Vec<u8>), aes_gcm::Error> {
        let mut raw_nonce: RawAeadNonce = [0; _];
        let mut nonce = self.nonce_rng.get_word_pos();
        while raw_nonce == [0; _] {
            nonce = self.nonce_rng.get_word_pos();
            self.nonce_rng.fill_bytes(&mut raw_nonce);
        }
        let payload = aead::Payload{
            msg: to_encrypt,
            aad: associated
        };

        let aead = RawAead::new(&self.key);
        let ciphertext = aead.encrypt(&raw_nonce.into(), payload);
        ciphertext.map(|encrypted| (nonce, encrypted))
    }

    pub fn decrypt(&mut self, nonce: u128, to_decrypt: &[u8], associated: &[u8]) -> Result<Vec<u8>, aes_gcm::Error> {
        let mut raw_nonce: RawAeadNonce = [0; _];
        if nonce < self.nonce_rng.get_word_pos() {return Err(aes_gcm::Error)}
        let old_count = self.nonce_rng.get_word_pos();
        self.nonce_rng.set_word_pos(nonce);
        self.nonce_rng.fill_bytes(&mut raw_nonce);
        let payload = aead::Payload{
            msg: to_decrypt,
            aad: associated
        };
        let aead = RawAead::new(&self.key);
        let result = aead.decrypt(&raw_nonce.into(), payload);
        if result.is_err() {self.nonce_rng.set_word_pos(old_count);}
        result
    }
}

#[derive(Debug)]
pub struct KemCipherText {
    pub(crate) cipher_text: RawCiphertext,
    pub(crate) key: RawSharedKey,
}

#[derive(PartialEq, Debug)]
pub struct EncapsulationKey{key: RawEncapsulationKey}

impl EncapsulationKey {
    pub fn encapsulate(&mut self, mut rng: impl OldCryptoRng + OldRngCore, key: &[u8]) -> Result<KemCipherText,()> {
        let (cipher_text, mut raw_key) = self.key.encapsulate(&mut rng)?;

        let mut xor_key = [0u8; _];
        #[allow(unused)] if false {xor_key = raw_key.clone().into();} // to allow the length to be inferred
        let length_len = 8;
        let written_len = key.len() + length_len;
        if written_len > raw_key.len() {return Err(())}
        xor_key[0..length_len].copy_from_slice(&(key.len() as u64).to_le_bytes());
        xor_key[length_len..written_len].copy_from_slice(&key);
        rng.fill_bytes(&mut xor_key[written_len..]);

        for (idx, byte) in xor_key.into_iter().enumerate() {
            raw_key[idx] ^= byte;
        }
        Ok(KemCipherText {
            cipher_text,
            key: raw_key
        })      
    }
}

#[derive(PartialEq, Debug)]
pub struct DecapsulationKey{key: RawDecapsulationKey}

impl DecapsulationKey {
    pub fn decapsulate(&mut self, cipher_text: KemCipherText) -> Result<impl Iterator<Item = u8>, ()> {
        let raw_key = self.key.decapsulate(&cipher_text.cipher_text)?;
        let mut key = cipher_text.key;
        for (byte, xor) in key.iter_mut().zip(raw_key.into_iter()) {
            *byte ^= xor;
        }
        let mut key = key.into_iter();
        // FIXME: usize bounding
        let len = read_u64(&mut key).map_err(|_| ())?;
        Ok(key.take(len as usize))
    }
}

pub fn get_kem_set(mut rng: impl OldCryptoRng + OldRngCore) -> (DecapsulationKey, EncapsulationKey) {
    let (raw_dk, raw_ek) = Kem::generate(&mut rng);
    (
        DecapsulationKey{key: raw_dk},
        EncapsulationKey{key: raw_ek}
    )
}

impl AsData for RawEncapsulationKey {
    fn size_hint(&self) -> usize {<Self as EncodedSizeUser>::EncodedSize::to_usize()}

    fn from_data_iter(data_iter: &mut impl Iterator<Item = u8>) -> Result<Self, DataError> where Self: Sized {
        Ok(Self::from_bytes(&data_iter.take(<Self as EncodedSizeUser>::EncodedSize::to_usize()).collect()))
    }

    fn extend_data(&self, data: &mut Vec<u8>) -> Result<(), DataError> {
        data.extend_from_slice(&self.as_bytes());
        Ok(())
    }
}

impl AsData for EncapsulationKey {
    fn size_hint(&self) -> usize {self.key.size_hint()}
    fn from_data_iter(data_iter: &mut impl Iterator<Item = u8>) -> Result<Self, DataError> where Self: Sized {
        let key = RawEncapsulationKey::from_data_iter(data_iter)?;
        Ok(EncapsulationKey { key })
    }
    fn extend_data(&self, data: &mut Vec<u8>) -> Result<(), DataError> {
        self.key.extend_data(data)?;
        Ok(())
    }
}

impl AsData for RawDecapsulationKey {
    fn size_hint(&self) -> usize {<Self as EncodedSizeUser>::EncodedSize::to_usize()}

    fn from_data_iter(data_iter: &mut impl Iterator<Item = u8>) -> Result<Self, DataError> where Self: Sized {
        Ok(Self::from_bytes(&data_iter.take(<Self as EncodedSizeUser>::EncodedSize::to_usize()).collect()))
    }

    fn extend_data(&self, data: &mut Vec<u8>) -> Result<(), DataError> {
        data.extend_from_slice(&self.as_bytes());
        Ok(())
    }
}

impl AsData for DecapsulationKey {
    fn size_hint(&self) -> usize {self.key.size_hint()}
    fn from_data_iter(data_iter: &mut impl Iterator<Item = u8>) -> Result<Self, DataError> where Self: Sized {
        let key = RawDecapsulationKey::from_data_iter(data_iter)?;
        Ok(DecapsulationKey { key })
    }
    fn extend_data(&self, data: &mut Vec<u8>) -> Result<(), DataError> {
        self.key.extend_data(data)?;
        Ok(())
    }
}

impl AsData for RawAeadKey {
    fn size_hint(&self) -> usize {<RawAead as KeySizeUser>::KeySize::to_usize()}

    fn from_data_iter(data_iter: &mut impl Iterator<Item = u8>) -> Result<Self, DataError> where Self: Sized {
        Ok(Self::clone_from_slice(&data_iter.take(<RawAead as KeySizeUser>::KeySize::to_usize()).collect::<Vec<_>>()))
    }
    fn extend_data(&self, data: &mut Vec<u8>) -> Result<(), DataError> {
        data.extend_from_slice(self.as_slice());
        Ok(())
    }
}

impl AsData for CryptoRng {
    fn size_hint(&self) -> usize {32 + 16 + 8}

    fn from_data_iter(data_iter: &mut impl Iterator<Item = u8>) -> Result<Self, DataError> where Self: Sized {
        let seed = read_arr::<32>(data_iter)?;
        let word_pos= read_u128(data_iter)?;
        let stream = read_u64(data_iter)?;
        let mut rng = CryptoRng::from_seed(seed);
        rng.set_word_pos(word_pos);
        rng.set_stream(stream);
        Ok(rng)
    }

    fn extend_data(&self, data: &mut Vec<u8>) -> Result<(), DataError> {
        let seed = self.get_seed();
        let word_pos = self.get_word_pos(); //really a 68 bit
        let stream = self.get_stream();
        data.extend_from_slice(&seed);
        data.extend_from_slice(&word_pos.to_le_bytes());
        data.extend_from_slice(&stream.to_le_bytes());
        Ok(())
    }
}

impl AsData for AeadKey {
    fn size_hint(&self) -> usize {self.key.size_hint() + self.nonce_rng.size_hint()}
    fn from_data_iter(data_iter: &mut impl Iterator<Item = u8>) -> Result<Self, DataError> where Self: Sized {
        let key = RawAeadKey::from_data_iter(data_iter)?;
        let nonce_rng = CryptoRng::from_data_iter(data_iter)?;
        Ok(Self{key, nonce_rng})
    }
    fn extend_data(&self, data: &mut Vec<u8>) -> Result<(), DataError> {
        self.key.extend_data(data)?;
        self.nonce_rng.extend_data(data)?;
        Ok(())
    }
}