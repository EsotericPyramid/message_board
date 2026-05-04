
use rand::distr::uniform::SampleRange;
use rand::seq::SliceRandom;
use rand::{distr::Distribution, Rng, RngExt};

// this is the 0.6.4 version, vs the 0.10.0 version from the rand crate
use rand_chacha::rand_core::RngCore as OldRngCore;
use rand_chacha::rand_core::CryptoRng as OldCryptoRng; 

use crate::*;
use crate::cryptography::{
    get_crypto_rng, 
    get_kem_set, 
    get_sys_rng, 
    UserAeadKey, 
    DecapsulationKey, 
    EncapsulationKey, 
    KEM_KEY_SIZE
};

const RANDOM_TEST_RETRIES: usize = 100;
const RANDOM_CHAR_RANGE: std::ops::Range<char> = '\u{0000}'..'\u{10ff}';

fn rand_bytes(mut rng: impl Rng, size_range: impl SampleRange<usize>) -> Vec<u8> {
    let data_size = rng.random_range(size_range);
    let mut data = vec![0u8; data_size];
    rng.fill_bytes(&mut data);
    data
}

fn get_char_rng(rng: impl Rng) -> impl Iterator<Item = char> {
    rand::distr::Uniform::try_from(RANDOM_CHAR_RANGE).unwrap().sample_iter(rng)
}

fn rand_defaulted_id_set(mut rng: impl Rng, _char_rng: impl Iterator<Item = char>) -> DefaultedIdSet {
    let default_base = match rng.random_range(0..3) {
        0 => DefaultBase::Inherit,
        1 => DefaultBase::White,
        2 => DefaultBase::Black,
        _ => panic!("access base type should be in range")
    };

    match default_base {
        DefaultBase::Inherit => {
            let num_whitelisted = rng.random_range(10..1000);
            let num_blacklisted = rng.random_range(10..1000);
            DefaultedIdSet::Inherit { 
                whitelist_ids: (&mut rng).random_iter().take(num_whitelisted).map(|x: u64| x.into()).collect(), 
                blacklist_ids: (&mut rng).random_iter().take(num_blacklisted).map(|x: u64| x.into()).collect(),
            }
        }
        DefaultBase::Black => {
            let num_whitelisted = rng.random_range(10..1000);
            DefaultedIdSet::Black {
                whitelist_ids: (&mut rng).random_iter().take(num_whitelisted).map(|x: u64| x.into()).collect(),
            }
        }
        DefaultBase::White => {
            let num_blacklisted = rng.random_range(10..1000);
            DefaultedIdSet::White { 
                blacklist_ids: (&mut rng).random_iter().take(num_blacklisted).map(|x: u64| x.into()).collect(),
            }
        }
    }
}

fn rand_entry(mut rng: impl Rng, mut char_rng: impl Iterator<Item = char>) -> Entry {
    let mut children_ids = Vec::new();
    for _ in 0..rng.random_range(1..100) {
        children_ids.push(rng.next_u64());
    }

    let entry_data = match rng.random_range(0..2) {
        0 => {
            EntryData::Message { 
                timestamp: rng.next_u64(), 
                message: char_rng.take(rng.random_range(100..10000)).collect::<String>(),
            }
        }
        1 => {
            EntryData::AccessGroup { 
                name: (&mut char_rng).take(rng.random_range(100..10000)).collect(), 
                write_perms: rand_defaulted_id_set(&mut rng, &mut char_rng),
                read_perms: rand_defaulted_id_set(&mut rng, &mut char_rng),
            }
        }
        _ => panic!("entry type should be in range")
    };

    let entry = Entry{
        entry_data,
        header_data: HeaderData { 
            version: ENTRY_FILE_VERSION, 
            parent_id: rng.next_u64(), 
            children_ids, 
            author_id: rng.next_u64().into(),
        },
    };

    entry
}

fn rand_user(mut rng: impl Rng, crypto_rng: impl OldCryptoRng + OldRngCore) -> UserData {
    let mut entry_ids = Vec::new();
    for _ in 0..rng.random_range(1..100) {
        entry_ids.push(rng.next_u64());
    }
    let aead = UserAeadKey::new_random(crypto_rng);
    let user = UserData { 
        aead,
        entry_ids
    };
    user
}

fn rand_request(mut rng: impl Rng, mut char_rng: impl Iterator<Item = char>) -> BoardRequest {
    match rng.random_range(0..5) {
        0 => {
            let user_id = rng.next_u64().into();
            let entry_id = rng.next_u64();
            BoardRequest::GetEntry { user_id, entry_id }
        }
        1 => {
            let user_id = rng.next_u64().into();
            let entry = rand_entry(&mut rng, &mut char_rng);
            BoardRequest::AddEntry { user_id, entry }
        }
        2 => {
            let user_id = rng.next_u64().into();
            let entry_id = rng.next_u64();
            let entry = rand_entry(&mut rng, &mut char_rng);
            BoardRequest::EditEntry { user_id, entry_id, entry }
        }
        3 => {
            let user_id = rng.next_u64().into();
            BoardRequest::GetUser { user_id }
        }
        4 => {
            BoardRequest::AddUser
        }
        _ => panic!("Request Type should be in range")
    }
}

fn new_rand_request(mut rng: impl Rng, mut char_rng: impl Iterator<Item = char>, sender_user_id: UserId) -> BoardRequest {
    match rng.random_range(0..5) {
        0 => {
            let entry_id = rng.next_u64();
            BoardRequest::GetEntry { user_id: sender_user_id, entry_id }
        }
        1 => {
            let entry = rand_entry(&mut rng, &mut char_rng);
            BoardRequest::AddEntry { user_id: sender_user_id, entry }
        }
        2 => {
            let entry_id = rng.next_u64();
            let entry = rand_entry(&mut rng, &mut char_rng);
            BoardRequest::EditEntry { user_id: sender_user_id, entry_id, entry }
        }
        3 => {
            let user_id = rng.next_u64().into();
            BoardRequest::GetUser { user_id }
        }
        4 => {
            BoardRequest::AddUser
        }
        _ => panic!("Request Type should be in range")
    }
}

fn rand_response(mut rng: impl Rng, char_rng: impl Iterator<Item = char>, crypto_rng: impl OldCryptoRng + OldRngCore) -> BoardResponse {
    match rng.random_range(0..6) {
        0 => {
            BoardResponse::GetEntry(rand_entry(rng, char_rng))
        }
        1 => {
            BoardResponse::AddEntry(rng.next_u64())
        }
        2 => {
            BoardResponse::EditEntry
        }
        3 => {
            BoardResponse::GetUser(rand_user(rng, crypto_rng))
        }
        4 => {
            BoardResponse::AddUser{
                user_id: rng.next_u64().into(), 
                user_aead: UserAeadKey::new_random(crypto_rng)
            }
        }
        5 => {
            BoardResponse::Error(internal_error!())
        }
        _ => panic!("Request Type should be in range")
    }
}

fn rand_re_encryptor(mut rng: impl Rng, crypto_rng: impl OldCryptoRng + OldRngCore, user_id: UserId) -> ReEncryptionData {
    match rng.random_range(0..3) {
        0 => ReEncryptionData::Exposed,
        1 => ReEncryptionData::FullAnonymous(SimpleAeadKey::new_random(crypto_rng)),
        2 => ReEncryptionData::User(user_id),
        _ => panic!("ReEncryptionData type should be in range")
    }
}

#[test]
fn entry_data_conversion() {
    let mut rng = rand::rng();
    let mut char_rng = get_char_rng(rng.clone());
    for _ in 0..RANDOM_TEST_RETRIES {
        let entry = rand_entry(&mut rng, &mut char_rng);
        assert_eq!(entry, Entry::from_data(&entry.into_data().unwrap()).unwrap(), "Invalid Entry Conversion");
    }
}

#[test]
fn entry_size_hint() {
    let mut rng = rand::rng();
    let mut char_rng = get_char_rng(rng.clone());
    for _ in 0..RANDOM_TEST_RETRIES {
        let entry = rand_entry(&mut rng, &mut char_rng);
        assert_eq!(entry.size_hint(), entry.into_data().unwrap().len(), "Incorrect size hint");
    }
}

#[test]
fn user_data_conversion() {
    let mut rng = rand::rng();
    let mut crypto_rng = get_crypto_rng();
    for _ in 0..RANDOM_TEST_RETRIES {
        let user = rand_user(&mut rng, &mut crypto_rng);
        assert_eq!(user, UserData::from_data(&user.into_data().unwrap()).unwrap(), "Invalid User Conversion");
    }
}

#[test]
fn user_size_hint() {
    let mut rng = rand::rng();
    let mut crypto_rng = get_crypto_rng();
    for _ in 0..RANDOM_TEST_RETRIES {
        let user = rand_user(&mut rng, &mut crypto_rng);
        assert_eq!(user.size_hint(), user.into_data().unwrap().len(), "Incorrect size hint");
    }
}

#[test]
fn request_data_conversion() {
    let mut rng = rand::rng();
    let mut char_rng = get_char_rng(rng.clone());
    for _ in 0..RANDOM_TEST_RETRIES {
        let request = rand_request(&mut rng, &mut char_rng);
        assert_eq!(request, BoardRequest::from_data(&request.into_data().unwrap()).unwrap(), "Invalid Request Conversion");
    }
}

#[test]
fn request_size_hint() {
    let mut rng = rand::rng();
    let mut char_rng = get_char_rng(rng.clone());
    for _ in 0..RANDOM_TEST_RETRIES {
        let request = rand_request(&mut rng, &mut char_rng);
        assert_eq!(request.size_hint(), request.into_data().unwrap().len(), "Incorrect size hint");
    }
}

#[test]
fn response_data_conversion() {
    let mut rng = rand::rng();
    let mut char_rng = get_char_rng(rng.clone());
    let mut crypto_rng = get_crypto_rng();
    for _ in 0..RANDOM_TEST_RETRIES {
        let response = rand_response(&mut rng, &mut char_rng, &mut crypto_rng);
        if let BoardResponse::Error(_) = response {
            let BoardResponse::Error(_) = BoardResponse::from_data(&response.into_data().unwrap()).unwrap() else {panic!("Invalid Request Conversion (Err)")};
        } else {
            assert_eq!(response, BoardResponse::from_data(&response.into_data().unwrap()).unwrap(), "Invalid Request Conversion");
        }
    }
}

#[test]
fn response_size_hint() {
    let mut rng = rand::rng();
    let mut char_rng = get_char_rng(rng.clone());
    let mut crypto_rng = get_crypto_rng();
    for _ in 0..RANDOM_TEST_RETRIES {
        let response = rand_response(&mut rng, &mut char_rng, &mut crypto_rng);
        assert_eq!(response.size_hint(), response.into_data().unwrap().len(), "Incorrect size hint");
    }
}

#[test]
fn kem_key_data_conversion() {
    let mut crypto_rng = get_crypto_rng();
    for _ in 0..RANDOM_TEST_RETRIES {
        let (dk, ek) = get_kem_set(&mut crypto_rng);
        assert_eq!(dk, DecapsulationKey::from_data(&dk.into_data().unwrap()).unwrap(), "Invalid Decapsulation Key Conversation");
        assert_eq!(ek, EncapsulationKey::from_data(&ek.into_data().unwrap()).unwrap(), "Invalid Encapsulation Key Conversation");
    }
}

#[test]
fn kem_key_size_hint() {
    let mut crypto_rng = get_crypto_rng();
    for _ in 0..RANDOM_TEST_RETRIES {
        let (dk, ek) = get_kem_set(&mut crypto_rng);
        assert_eq!(dk.size_hint(), dk.into_data().unwrap().len(), "Invalid Decapsulation Size Hint");
        assert_eq!(ek.size_hint(), ek.into_data().unwrap().len(), "Invalid Encapsulation Size Hint");
    }
}

#[test]
fn kem() {
    let mut rng = rand::rng();
    let mut crypto_rng = get_crypto_rng();
    let (dk, ek) = get_kem_set(get_sys_rng());
    for _ in 0..RANDOM_TEST_RETRIES {
        let data = rand_bytes(&mut rng, 0..=KEM_KEY_SIZE);
        let ct = ek.encapsulate(&mut crypto_rng, &data).unwrap();
        let sk = dk.decapsulate(ct, data.len()).unwrap().collect::<Vec<_>>();
        assert_eq!(data, sk);
    }
}

#[test]
fn kem_size_check() {
    let mut rng = rand::rng();
    let mut crypto_rng = get_crypto_rng();
    let (_, ek) = get_kem_set(get_sys_rng());
    for _ in 0..RANDOM_TEST_RETRIES {
        let data = rand_bytes(&mut rng, KEM_KEY_SIZE+1..KEM_KEY_SIZE + 128);
        let _ = ek.encapsulate(&mut crypto_rng, &data).expect_err("Kem Encapsulation incorrectly succeeded");
    }
}

#[test]
fn aead_data_conversion() {
    let mut rng = get_crypto_rng();
    for _ in 0..RANDOM_TEST_RETRIES {
        let key = UserAeadKey::new_random(&mut rng);
        assert_eq!(key, UserAeadKey::from_data(&key.into_data().unwrap()).unwrap(), "Invalid UserAeadKey Converstion");
    }
}

#[test]
fn aead_size_hint() {
    let mut rng = get_crypto_rng();
    for _ in 0..RANDOM_TEST_RETRIES {
        let key = UserAeadKey::new_random(&mut rng);
        assert_eq!(key.size_hint(), key.into_data().unwrap().len(), "Invalid Size Hint");
    }
}

#[test]
fn aead() {
    let mut rng = rand::rng();
    let mut encrypt_key = UserAeadKey::new_random(get_sys_rng());
    let mut decrypt_key = encrypt_key.clone();

    for _ in 0..RANDOM_TEST_RETRIES {
        let data = rand_bytes(&mut rng, 0..65536);
        let associated = rand_bytes(&mut rng, 0..256);
        let (nonce, encrypted)= encrypt_key.encrypt(&data, &associated).unwrap();
        let decrypted = decrypt_key.decrypt(nonce, &encrypted, &associated).unwrap();
        assert_eq!(data, decrypted);
    }
}

#[test]
fn aead_replay_attack() {
    let mut rng = rand::rng();
    let mut encrypt_key = UserAeadKey::new_random(get_sys_rng());
    let mut decrypt_key = encrypt_key.clone();

    // get it into a real state
    for _ in 0..10 {
        let data = rand_bytes(&mut rng, 0..65536);
        let associated = rand_bytes(&mut rng, 0..256);
        let (nonce, encrypted)= encrypt_key.encrypt(&data, &associated).unwrap();
        let _ = decrypt_key.decrypt(nonce, &encrypted, &associated).unwrap();
    }

    let data = rand_bytes(&mut rng, 0..65536);
    let associated = rand_bytes(&mut rng, 0..256);
    let (nonce, encrypted)= encrypt_key.encrypt(&data, &associated).unwrap();
    let _ = decrypt_key.decrypt(nonce, &encrypted, &associated).unwrap();
    let _ = decrypt_key.decrypt(nonce, &encrypted, &associated).expect_err("Replay attack succeeded in basic case"); // <-- should panic here
}

#[test]
fn aead_incorrect_nonce() {
    let mut rng = rand::rng();
    let mut encrypt_key = UserAeadKey::new_random(get_sys_rng());
    let mut decrypt_key = encrypt_key.clone();

    for _ in 0..RANDOM_TEST_RETRIES {
        let data = rand_bytes(&mut rng, 0..65536);
        let associated = rand_bytes(&mut rng, 0..256);
        let (nonce, encrypted)= encrypt_key.encrypt(&data, &associated).unwrap();
        if rng.random() {
            let decrypted = decrypt_key.decrypt(nonce, &encrypted, &associated).unwrap(); 
            assert_eq!(data, decrypted, "Incorrect Nonce Broke the decryptor");
        } else {
            let mut incorrect_nonce = nonce;
            while incorrect_nonce == nonce {
                incorrect_nonce = rng.random::<u128>() % AEAD_NONCE_MOD;
            }
            if let Ok(decrypted) = decrypt_key.decrypt(incorrect_nonce, &encrypted, &associated) { // <-- should fail here (astronomical chance that it may result in a "valid" decryption anyways)
                assert_ne!(data, decrypted, "Incorrect Nonce can extract data")
            } 
        }
    }
}

#[test]
fn secure_board_request_data_conversion() {
    let mut rng = rand::rng();
    let mut char_rng = get_char_rng(rng.clone());
    let mut crypto_rng = get_crypto_rng();

    let user_id = rng.random::<u64>().into();
    let mut server_aead_key = UserAeadKey::new_random(&mut crypto_rng);
    let user_aead_key = server_aead_key.clone();
    let (kem_dk, kem_ek) = get_kem_set(&mut crypto_rng);
    let mut user_key = PublicKeySet::new(Some(kem_ek), Some(user_aead_key));
    for _ in 0..RANDOM_TEST_RETRIES {
        let request = new_rand_request(&mut rng, &mut char_rng, user_id);
        let encoded = request.secure_into_data(&mut crypto_rng, &mut user_key).unwrap();
        let (_, decoded) = BoardRequest::secure_from_data(&kem_dk, |x| if x == user_id {Some(&mut server_aead_key)} else {None}, &encoded).unwrap();
        assert_eq!(request, decoded);
    }
}

#[test]
fn secure_board_batched_request_data_conversion() {
    let mut rng = rand::rng();
    let mut char_rng = get_char_rng(rng.clone());
    let mut crypto_rng = get_crypto_rng();

    let user_id = rng.random::<u64>().into();
    let mut server_aead_key = UserAeadKey::new_random(&mut crypto_rng);
    let user_aead_key = server_aead_key.clone();
    let (kem_dk, kem_ek) = get_kem_set(&mut crypto_rng);
    let mut user_key = PublicKeySet::new(Some(kem_ek), Some(user_aead_key));
    for _ in 0..RANDOM_TEST_RETRIES {
        let mut request_batch = Vec::new();
        for _ in 0..AEAD_NONCE_MEMORY + 1 {
            request_batch.push(new_rand_request(&mut rng, &mut char_rng, user_id))
        }

        let mut encoded_batch = request_batch.iter().map(|x| x.secure_into_data(&mut crypto_rng, &mut user_key).unwrap()).enumerate().collect::<Vec<_>>();
        encoded_batch.shuffle(&mut rng);
        for (idx, encoded) in encoded_batch {
            let (_, decoded) = BoardRequest::secure_from_data(&kem_dk, |x| if x == user_id {Some(&mut server_aead_key)} else {None}, &encoded).unwrap();
            assert_eq!(request_batch[idx], decoded);
        }
    }
}

#[test]
fn secure_board_response_data_conversion() {
    let mut rng = rand::rng();
    let mut char_rng = get_char_rng(rng.clone());
    let mut crypto_rng = get_crypto_rng();

    let user_id = rng.random::<u64>().into();
    let mut servers_user_aead_key = UserAeadKey::new_random(&mut crypto_rng);
    let users_user_aead_key = servers_user_aead_key.clone();

    let (_kem_dk, kem_ek) = get_kem_set(&mut crypto_rng);
    let mut user_key = PublicKeySet::new(Some(kem_ek), Some(users_user_aead_key));

    for _ in 0..RANDOM_TEST_RETRIES {
        let response = rand_response(&mut rng, &mut char_rng, &mut crypto_rng);
        let re_encryptor = rand_re_encryptor(&mut rng, &mut crypto_rng, user_id);
        if let ReEncryptionData::FullAnonymous(key) = &re_encryptor {
            user_key.simple_aead.push_back(key.clone()); // this has to be artificial since it would normally be done when the request leading to this response was sent
        }
        let encoded = response.secure_into_data(&mut crypto_rng, re_encryptor,  |key_user_id| 
            if key_user_id == user_id {Some(&mut servers_user_aead_key)} else {None}
        ).unwrap();
        let decoded = BoardResponse::secure_from_data(&encoded, &mut user_key).unwrap();
        if let BoardResponse::Error(_) = response {
            let BoardResponse::Error(_) = decoded else {panic!("Invalid Request Conversion (Err)")};
        } else {
            assert_eq!(response, decoded, "Invalid Request Conversion");
        }
    }
}