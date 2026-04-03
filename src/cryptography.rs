use aes_gcm::aead::{self, Aead};
use aes_gcm::{AeadCore, KeyInit, KeySizeUser};
use ml_kem::EncodedSizeUser;
use typenum::marker_traits::Unsigned;
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::rand_core::RngCore;

use super::*;

type CryptoRng = rand_chacha::ChaCha20Rng;

type KemParams = ml_kem::MlKem1024Params;
type Encapsulator = ml_kem::kem::EncapsulationKey<KemParams>;
type Decapsulator = ml_kem::kem::DecapsulationKey<KemParams>;

type RawAead = aes_gcm::Aes256Gcm;
type RawAeadKey = aes_gcm::Key<RawAead>;
type RawAeadNonce = [u8; 12];

struct AeadKey {
    key: RawAeadKey,
    nonce_rng: CryptoRng,
}

impl AeadKey {
    fn new_random(mut rng: impl rand::CryptoRng) -> Self {
        let mut seed= [0u8; 32];
        rng.fill_bytes(&mut seed);
        let mut rng = CryptoRng::from_seed(seed); // getting an rng Aead is happy working with (from rand 0.6.4, not 0.10.0)

        let key = RawAead::generate_key(&mut rng);
        let mut nonce_seed= [0u8; 32];
        rng.fill_bytes(&mut nonce_seed);
        let nonce_rng = CryptoRng::from_seed(seed);
        let mut counter: [u8; 16] = [0; _];
        rng.fill_bytes(&mut counter);
        let counter = u128::from_ne_bytes(counter);
        Self { key, nonce_rng }
    }

    fn encrypt(&mut self, to_encrypt: &[u8], associated: &[u8]) -> Result<(u128, Vec<u8>), aes_gcm::Error> {
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

    fn decrypt(&mut self, nonce: u128, to_decrypt: &[u8], associated: &[u8]) -> Result<Vec<u8>, aes_gcm::Error> {
        let mut raw_nonce: RawAeadNonce = [0; _];
        if nonce <= self.nonce_rng.get_word_pos() {return Err(aes_gcm::Error)}
        self.nonce_rng.set_word_pos(nonce);
        self.nonce_rng.fill_bytes(&mut raw_nonce);
        let payload = aead::Payload{
            msg: to_decrypt,
            aad: associated
        };
        let aead = RawAead::new(&self.key);
        aead.decrypt(&raw_nonce.into(), payload)
    }
}

impl AsData for Encapsulator {
    fn size_hint(&self) -> usize {<Self as EncodedSizeUser>::EncodedSize::to_usize()}

    fn from_data_iter(data_iter: &mut impl Iterator<Item = u8>) -> Result<Self, DataError> where Self: Sized {
        Ok(Self::from_bytes(&data_iter.take(<Self as EncodedSizeUser>::EncodedSize::to_usize()).collect()))
    }

    fn extend_data(&self, data: &mut Vec<u8>) -> Result<(), DataError> {
        data.extend_from_slice(&self.as_bytes());
        Ok(())
    }
}

impl AsData for Decapsulator {
    fn size_hint(&self) -> usize {<Self as EncodedSizeUser>::EncodedSize::to_usize()}

    fn from_data_iter(data_iter: &mut impl Iterator<Item = u8>) -> Result<Self, DataError> where Self: Sized {
        Ok(Self::from_bytes(&data_iter.take(<Self as EncodedSizeUser>::EncodedSize::to_usize()).collect()))
    }

    fn extend_data(&self, data: &mut Vec<u8>) -> Result<(), DataError> {
        data.extend_from_slice(&self.as_bytes());
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
        let word_pos = self.get_word_pos();
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