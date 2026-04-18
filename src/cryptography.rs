use std::collections::VecDeque;

use aes_gcm::{KeyInit, KeySizeUser};
use ml_kem::array::AssocArraySize;
use aes_gcm::aead::{self, Aead};
use ml_kem::{EncodedSizeUser, KemCore};
use ml_kem::kem::{Encapsulate, Decapsulate};
use typenum::marker_traits::Unsigned;
use rand_chacha::rand_core::SeedableRng;
// this is the 0.6.4 version, vs the 0.10.0 version from the rand crate
use rand_chacha::rand_core::RngCore as OldRngCore;
use rand_chacha::rand_core::CryptoRng as OldCryptoRng; 

use super::*;

pub type CryptoRng = rand_chacha::ChaCha20Rng;
pub type OldSysRng = rand_chacha::rand_core::OsRng;

type KemParams = ml_kem::MlKem1024Params;
type Kem = ml_kem::kem::Kem<KemParams>;
type RawEncapsulationKey = ml_kem::kem::EncapsulationKey<KemParams>;
type RawDecapsulationKey = ml_kem::kem::DecapsulationKey<KemParams>;
pub type RawKemCipherText = ml_kem::Ciphertext<Kem>;
pub type RawSharedKey = ml_kem::SharedKey<Kem>;
pub const KEM_KEY_SIZE: usize = 32;

type RawAead = aes_gcm::Aes256Gcm;
pub type RawAeadKey = aes_gcm::Key<RawAead>;
type RawAeadNonce = [u8; 12];
pub const AEAD_NONCE_MEMORY: usize = 4;
const AEAD_NONCE_RNG_STRIDE: u128 = 3; // in words, needs to be tested
pub const AEAD_NONCE_BIT_LENGTH: u128 = 68;
pub const AEAD_NONCE_MAX: u128 = AEAD_NONCE_MOD -1; //its actually only 68 bit
pub const AEAD_NONCE_MOD: u128 = 1 << AEAD_NONCE_BIT_LENGTH;

impl AsData for RawKemCipherText {
    fn size_hint(&self) -> usize {self.len()}
    fn from_data_iter(data_iter: &mut impl Iterator<Item = u8>) -> Result<Self, DataError> where Self: Sized {
        Ok(data_iter.take(<RawKemCipherText as AssocArraySize>::Size::to_usize()).collect())
    }
    fn extend_data(&self, data: &mut Vec<u8>) -> Result<(), DataError> {
        Ok(data.extend_from_slice(&self))
    }
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

pub fn get_crypto_rng() -> CryptoRng {rand_chacha::ChaCha20Rng::from_rng(get_sys_rng()).unwrap()}
pub fn get_full_rand_crypto_rng(mut rng: impl OldCryptoRng + OldRngCore) -> CryptoRng {
    let mut crypto_seed= [0u8; 32];
    rng.fill_bytes(&mut crypto_seed);
    let mut crypto_rng = CryptoRng::from_seed(crypto_seed);
    let mut crypto_rng_start: [u8; 16] = [0; _];
    rng.fill_bytes(&mut crypto_rng_start);
    let crypto_rng_start = u128::from_ne_bytes(crypto_rng_start);
    crypto_rng.set_word_pos(crypto_rng_start);
    crypto_rng.set_stream(rng.next_u64());
    crypto_rng
}
pub const fn get_sys_rng() -> OldSysRng {rand_chacha::rand_core::OsRng}

/// security note: this key *does not use nonces* and as such shouldn't be used to repeated encryption / decryption, use UserAeadKey for that
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SimpleAeadKey {
    key: RawAeadKey,
}

impl SimpleAeadKey {
    pub fn new_random(mut rng: impl OldCryptoRng + OldRngCore) -> Self {
        let key = RawAead::generate_key(&mut rng);
        Self{ key }
    }

    pub fn new_from_key(raw_key: RawAeadKey) -> Self {
        Self{ key: raw_key }
    }

    pub fn encrypt(&self, to_encrypt: &[u8], associated: &[u8]) -> Result<Vec<u8>, DataError> {
        let payload = aead::Payload{
            msg: to_encrypt,
            aad: associated
        };
        let aead = RawAead::new(&self.key);
        Ok(aead.encrypt(&[0u8; _].into(), payload)?)
    }

    pub fn decrypt(&self, to_decrypt: &[u8], associated: &[u8]) -> Result<Vec<u8>, DataError> {
        let payload = aead::Payload{
            msg: to_decrypt,
            aad: associated
        };
        let aead = RawAead::new(&self.key);
        Ok(aead.decrypt(&[0u8; _].into(), payload)?)
    }
}

impl AsData for SimpleAeadKey {
    fn size_hint(&self) -> usize {self.key.size_hint()}
    fn from_data_iter(data_iter: &mut impl Iterator<Item = u8>) -> Result<Self, DataError> where Self: Sized {
        let key = RawAeadKey::from_data_iter(data_iter)?;
        Ok(Self { key })
    }
    fn extend_data(&self, data: &mut Vec<u8>) -> Result<(), DataError> {self.key.extend_data(data)}
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct UserAeadKey {
    key: RawAeadKey,
    nonce_rng: CryptoRng,
    old_nonces: VecDeque<u128>,
}

impl UserAeadKey {
    pub fn new_random(mut rng: impl OldCryptoRng + OldRngCore) -> Self {
        let key = RawAead::generate_key(&mut rng);
        let nonce_rng = get_full_rand_crypto_rng(rng);
        Self { key, nonce_rng, old_nonces: VecDeque::new() }
    }

    pub fn derive_simple_key(&self) -> SimpleAeadKey {
        SimpleAeadKey::new_from_key(self.key.clone())
    }

    fn increment_nonce(&mut self) -> (u128, RawAeadNonce) {
        let mut raw_nonce: RawAeadNonce = [0; _];
        let nonce = self.nonce_rng.get_word_pos();
        self.nonce_rng.fill_bytes(&mut raw_nonce);
        (nonce, raw_nonce)
    }

    fn add_old_nonce(&mut self, nonce: u128) {
        if self.old_nonces.len() >= AEAD_NONCE_MEMORY {self.old_nonces.pop_front();}
        self.old_nonces.push_back(nonce);
    }

    pub fn encrypt(&mut self, to_encrypt: &[u8], associated: &[u8]) -> Result<(u128, Vec<u8>), DataError> {
        let (nonce, raw_nonce) = self.increment_nonce();
        self.add_old_nonce(nonce);
        let payload = aead::Payload{
            msg: to_encrypt,
            aad: associated
        };

        let aead = RawAead::new(&self.key);
        let ciphertext = aead.encrypt(&raw_nonce.into(), payload)?;
        Ok((nonce, ciphertext))
    }

    pub fn decrypt(&mut self, nonce: u128, to_decrypt: &[u8], associated: &[u8]) -> Result<Vec<u8>, DataError> {
        fn inner(key: &UserAeadKey, raw_nonce: RawAeadNonce, payload: aead::Payload<'_, '_>) -> Result<Vec<u8>, DataError> {
            let aead = RawAead::new(&key.key);
            let result = aead.decrypt(&raw_nonce.into(), payload);
            Ok(result?)
        }

        if nonce > AEAD_NONCE_MAX {return Err(DataError::EncryptionError)}
        let payload = aead::Payload{
            msg: to_decrypt,
            aad: associated
        };
        
        if nonce < self.nonce_rng.get_word_pos() {
            if let Ok(idx) = self.old_nonces.binary_search(&nonce) {
                let old_count = self.nonce_rng.get_word_pos();
                self.nonce_rng.set_word_pos(nonce);
                let (_, raw_nonce) = self.increment_nonce();
                let result = inner(&self, raw_nonce, payload);
                if result.is_ok() {
                    self.old_nonces.remove(idx);
                }
                self.nonce_rng.set_word_pos(old_count);
                result
            } else {
                return Err(aes_gcm::Error.into())
            }
        } else {
            // this could prolly be better, but i can't be bothered
            let old_head = self.nonce_rng.get_word_pos();
            let old_old_nonces = self.old_nonces.clone();
            
            if nonce > self.nonce_rng.get_word_pos() {
                // note: this is probably excessive, i may choose to disallow changing position in a stride
                self.add_old_nonce(old_head);
                let mut new_stride_start = old_head + (nonce % AEAD_NONCE_RNG_STRIDE) - (old_head % AEAD_NONCE_RNG_STRIDE);
                let num_nonces_jumped = (nonce - new_stride_start) / AEAD_NONCE_RNG_STRIDE;
                if num_nonces_jumped > 4 {
                    new_stride_start += (num_nonces_jumped - 4) * AEAD_NONCE_RNG_STRIDE;
                }
                self.nonce_rng.set_word_pos(new_stride_start);
            }
            let (mut current_nonce, mut raw_nonce) = self.increment_nonce();
            while current_nonce < nonce {
                self.add_old_nonce(current_nonce);
                (current_nonce, raw_nonce) = self.increment_nonce();
            }
            let result = inner(&self, raw_nonce, payload);
            if result.is_err() {
                self.nonce_rng.set_word_pos(old_head);
                self.old_nonces = old_old_nonces;
            }
            result
        }
    }
}

impl AsData for UserAeadKey {
    fn size_hint(&self) -> usize {self.key.size_hint() + self.nonce_rng.size_hint()}
    fn from_data_iter(data_iter: &mut impl Iterator<Item = u8>) -> Result<Self, DataError> where Self: Sized {
        let key = RawAeadKey::from_data_iter(data_iter)?;
        let nonce_rng = CryptoRng::from_data_iter(data_iter)?;
        Ok(Self{key, nonce_rng, old_nonces: VecDeque::new()})
    }
    fn extend_data(&self, data: &mut Vec<u8>) -> Result<(), DataError> {
        self.key.extend_data(data)?;
        self.nonce_rng.extend_data(data)?;
        Ok(())
    }
}


#[derive(Debug)]
pub struct KemCipherText {
    pub(crate) cipher_text: RawKemCipherText,
    pub(crate) key: RawSharedKey,
}

impl AsData for KemCipherText {
    fn size_hint(&self) -> usize {self.cipher_text.size_hint() + self.key.len()}
    fn from_data_iter(data_iter: &mut impl Iterator<Item = u8>) -> Result<Self, DataError> where Self: Sized {
        let cipher_text = RawKemCipherText::from_data_iter(data_iter)?;
        let key = data_iter.take(<RawSharedKey as AssocArraySize>::Size::to_usize()).collect();
        Ok(Self {
            cipher_text,
            key
        })
    }
    fn extend_data(&self, data: &mut Vec<u8>) -> Result<(), DataError> {
        self.cipher_text.extend_data(data)?;
        data.extend_from_slice(&self.key);
        Ok(())
    }
}


#[derive(PartialEq, Debug)]
pub struct EncapsulationKey{key: RawEncapsulationKey}

impl EncapsulationKey {
    pub fn encapsulate(&self, mut rng: impl OldCryptoRng + OldRngCore, key: &[u8]) -> Result<KemCipherText, DataError> {
        let (cipher_text, mut raw_key) = self.key.encapsulate(&mut rng).map_err(|_| DataError::EncryptionError)?;

        let mut xor_key = [0u8; _];
        #[allow(unused)] if false {xor_key = raw_key.clone().into();} // to allow the length to be inferred
        if key.len() > raw_key.len() {return Err(DataError::EncryptionError)}
        xor_key[0..key.len()].copy_from_slice(&key);
        rng.fill_bytes(&mut xor_key[key.len()..]);

        for (idx, byte) in xor_key.into_iter().enumerate() {
            raw_key[idx] ^= byte;
        }
        Ok(KemCipherText {
            cipher_text,
            key: raw_key
        })      
    }

    pub fn raw_encapsulate(&self, mut rng: impl OldCryptoRng + OldRngCore) -> Result<(RawKemCipherText, RawSharedKey), DataError> {self.key.encapsulate(&mut rng).map_err(|_| DataError::EncryptionError)}
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


#[derive(PartialEq, Debug)]
pub struct DecapsulationKey{key: RawDecapsulationKey}

impl DecapsulationKey {
    pub fn decapsulate(&self, cipher_text: KemCipherText, len: usize) -> Result<impl Iterator<Item = u8>, DataError> {
        let raw_key = self.key.decapsulate(&cipher_text.cipher_text).map_err(|_| DataError::EncryptionError)?;
        let mut key = cipher_text.key;
        for (byte, xor) in key.iter_mut().zip(raw_key.into_iter()) {
            *byte ^= xor;
        }
        if len > key.len() {return Err(DataError::EncryptionError)}
        let key = key.into_iter();
        Ok(key.take(len as usize))    
    }

    pub fn raw_decapsulate(&self, cipher_text: RawKemCipherText) -> Result<RawSharedKey, DataError> {self.key.decapsulate(&cipher_text).map_err(|_| DataError::EncryptionError)}
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


pub fn get_kem_set(mut rng: impl OldCryptoRng + OldRngCore) -> (DecapsulationKey, EncapsulationKey) {
    let (raw_dk, raw_ek) = Kem::generate(&mut rng);
    (
        DecapsulationKey{key: raw_dk},
        EncapsulationKey{key: raw_ek}
    )
}

pub fn extend_with_exposed_block(output_stream: &mut Vec<u8>, to_encode: &[u8]) -> Result<(), DataError> {
    bounded_usize!(to_encode.len(), u64)?;
    output_stream.extend_from_slice(&(to_encode.len() as u64).to_le_bytes());
    output_stream.extend_from_slice(to_encode);
    Ok(())
}

pub fn read_from_exposed_block(input_stream: &mut impl Iterator<Item = u8>) -> Result<impl Iterator<Item = u8>, DataError> {
    let len = read_u64(input_stream)?;
    Ok(input_stream.take(len as usize))
}

pub fn extend_with_full_anonymous_block(rng: impl OldCryptoRng + OldRngCore, keys: &mut PublicKeySet, output_stream: &mut Vec<u8>, to_encrypt: &[u8]) -> Result<SimpleAeadKey, DataError> {
    let (kem_ct, kem_sk) = keys.kem.raw_encapsulate(rng)?;
    let mut aead_key: [u8; _] = [0; _];
    for i in 0..aead_key.len() {
        aead_key[i] = kem_sk[i % kem_sk.len()];
    }
    let aead = SimpleAeadKey::new_from_key(aead_key.into());
    // todo: see if I want to use any associated data
    let aead_ct = aead.encrypt(to_encrypt, &[])?;
    output_stream.extend_from_slice(&kem_ct);
    bounded_usize!(aead_ct.len(), u64)?;
    output_stream.extend_from_slice(&(aead_ct.len() as u64).to_le_bytes());
    output_stream.extend_from_slice(&aead_ct);
    Ok(aead)
}

pub fn read_from_full_anonymous_block(kem_dk: &DecapsulationKey, input_stream: &mut impl Iterator<Item = u8>) -> Result<(SimpleAeadKey, Vec<u8>), DataError> {
    let mut kem_ct: RawKemCipherText = [0u8; _].into();
    kem_ct = input_stream.take(kem_ct.len()).collect();
    let kem_sk = kem_dk.raw_decapsulate(kem_ct)?;
    let mut aead_key: [u8; _] = [0; _];
    for i in 0..aead_key.len() {
        aead_key[i] = kem_sk[i % kem_sk.len()];
    }
    let aead = SimpleAeadKey::new_from_key(aead_key.into());

    let aead_len = read_u64(input_stream)? as usize;
    let aead_pt = aead.decrypt(&input_stream.take(aead_len).collect::<Vec<_>>(), &[])?;
    Ok((aead, aead_pt))
}

pub fn extend_with_user_block(mut rng: impl OldCryptoRng + OldRngCore, keys: &mut PublicKeySet, user_id: u64, output_stream: &mut Vec<u8>, to_encrypt: &[u8]) -> Result<(), DataError> {
    let Some(aead) = keys.user_aead.as_mut() else {return Err(DataError::MissingKey);};
    // todo: see if I want to use any associated data
    let (nonce, aead_ct) = aead.encrypt(to_encrypt, &[])?;
    let mut kem_sk: Vec<u8> = Vec::new();
    kem_sk.extend_from_slice(&user_id.to_le_bytes());
    let nonce_mask: u128 = (rng.next_u64() as u128) << AEAD_NONCE_BIT_LENGTH;
    kem_sk.extend_from_slice(&(nonce ^ nonce_mask).to_le_bytes());
    let kem_ct = keys.kem.encapsulate(rng, &kem_sk)?;
    kem_ct.extend_data(output_stream)?;
    bounded_usize!(aead_ct.len(), u64)?;
    output_stream.extend_from_slice(&(aead_ct.len() as u64).to_le_bytes());
    output_stream.extend_from_slice(&aead_ct);
    Ok(())
}

pub fn read_from_user_block<'a, F: FnOnce(u64) -> Option<&'a mut UserAeadKey>>(kem_dk: &DecapsulationKey, input_stream: &mut impl Iterator<Item = u8>, get_user_aead: F) -> Result<(u64, Vec<u8>), DataError> {
    let kem_ct = KemCipherText::from_data_iter(input_stream)?;
    let mut packed_kem_sk = kem_dk.decapsulate(kem_ct, 8 + 16)?;
    let user_id = read_u64(&mut packed_kem_sk)?;
    let nonce = read_u128(&mut packed_kem_sk)? & AEAD_NONCE_MAX;
    let aead = get_user_aead(user_id).map_or(Err(DataError::MissingKey), |x| Ok(x))?;
    let aead_len = read_u64(input_stream)? as usize;
    let aead_pt = aead.decrypt(nonce, &input_stream.take(aead_len).collect::<Vec<_>>(), &[])?;
    Ok((user_id, aead_pt))
}

pub fn extend_with_full_anonymous_response_block(key: &SimpleAeadKey, output_stream: &mut Vec<u8>, to_encrypt: &[u8]) -> Result<(), DataError> {
    let ct = key.encrypt(to_encrypt, &[])?;
    bounded_usize!(ct.len(), u64)?;
    output_stream.extend_from_slice(&(ct.len() as u64).to_le_bytes());
    output_stream.extend_from_slice(&ct);
    Ok(())
}

pub fn read_from_full_anonymous_response_block<'a>(keys: impl Iterator<Item = &'a SimpleAeadKey>, input_stream: &mut impl Iterator<Item = u8>) -> Result<(&'a SimpleAeadKey, Vec<u8>), DataError> {
    let len = read_u64(input_stream)?;
    let ct = input_stream.take(len as usize).collect::<Vec<_>>();
    for key in keys {
        if let Ok(pt) = key.decrypt(&ct, &[]) {
            return Ok((key, pt));
        }
    }
    return Err(DataError::MissingKey);
}

pub fn extend_with_user_response_block(mut rng: impl OldCryptoRng + OldRngCore, key: &mut UserAeadKey, output_stream: &mut Vec<u8>, to_encrypt: &[u8]) -> Result<(), DataError> {
    let simple_key = key.derive_simple_key();
    let (mut nonce, body_ct) = key.encrypt(to_encrypt, &[])?;
    nonce ^= (rng.next_u64() as u128) << AEAD_NONCE_BIT_LENGTH;
    let header_ct = simple_key.encrypt(&nonce.to_le_bytes(), &[])?;

    bounded_usize!(header_ct.len(), u16)?;
    output_stream.extend_from_slice(&(header_ct.len() as u16).to_le_bytes()); // note: this probably isn't needed
    output_stream.extend_from_slice(&header_ct);
    bounded_usize!(body_ct.len(), u64)?;
    output_stream.extend_from_slice(&(body_ct.len() as u64).to_le_bytes());
    output_stream.extend_from_slice(&body_ct);
    Ok(())
}

pub fn read_from_user_response_block(key: &mut UserAeadKey, input_stream: &mut impl Iterator<Item = u8>) -> Result<Vec<u8>, DataError> {
    let simple_key = key.derive_simple_key();

    let header_ct_len = read_u16(input_stream)?;
    let header_ct = input_stream.take(header_ct_len as usize).collect::<Vec<_>>();
    let nonce: [u8; 16] = simple_key.decrypt(&header_ct, &[])?.try_into().map_err(|_| internal_error!())?;
    let nonce = u128::from_le_bytes(nonce) % AEAD_NONCE_MOD;

    let body_ct_len = read_u64(input_stream)?;
    let body_ct = input_stream.take(body_ct_len as usize).collect::<Vec<_>>();
    key.decrypt(nonce, &body_ct, &[])
}