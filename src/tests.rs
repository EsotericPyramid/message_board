use rand::distr::uniform::SampleRange;
use rand::{distr::Distribution, Rng, RngExt};

use crate::*;
use crate::cryptography::{AeadKey, get_sys_rng};

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
                whitelist_ids: (&mut rng).random_iter().take(num_whitelisted).collect(), 
                blacklist_ids: (&mut rng).random_iter().take(num_blacklisted).collect(),
            }
        }
        DefaultBase::Black => {
            let num_whitelisted = rng.random_range(10..1000);
            DefaultedIdSet::Black {
                whitelist_ids: (&mut rng).random_iter().take(num_whitelisted).collect(),
            }
        }
        DefaultBase::White => {
            let num_blacklisted = rng.random_range(10..1000);
            DefaultedIdSet::White { 
                blacklist_ids: (&mut rng).random_iter().take(num_blacklisted).collect(),
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
            author_id: rng.next_u64(),
        },
    };

    entry
}

fn rand_user(mut rng: impl Rng, _char_rng: impl Iterator<Item = char>) -> UserData {
    let mut entry_ids = Vec::new();
    for _ in 0..rng.random_range(1..100) {
        entry_ids.push(rng.next_u64());
    }

    let user = UserData { entry_ids };
    user
}

fn rand_request(mut rng: impl Rng, mut char_rng: impl Iterator<Item = char>) -> BoardRequest {
    match rng.random_range(0..5) {
        0 => {
            let user_id = rng.next_u64();
            let entry_id = rng.next_u64();
            BoardRequest::GetEntry { user_id, entry_id }
        }
        1 => {
            let user_id = rng.next_u64();
            let entry = rand_entry(&mut rng, &mut char_rng);
            BoardRequest::AddEntry { user_id, entry }
        }
        2 => {
            let user_id = rng.next_u64();
            let entry_id = rng.next_u64();
            let entry = rand_entry(&mut rng, &mut char_rng);
            BoardRequest::EditEntry { user_id, entry_id, entry }
        }
        3 => {
            let user_id = rng.next_u64();
            BoardRequest::GetUser { user_id }
        }
        4 => {
            BoardRequest::AddUser
        }
        _ => panic!("Request Type should be in range")
    }
}

fn rand_response(mut rng: impl Rng, char_rng: impl Iterator<Item = char>) -> MaybeBoardResponse {
    match rng.random_range(0..5) {
        0 => {
            Ok(BoardResponse::GetEntry(rand_entry(rng, char_rng)))
        }
        1 => {
            Ok(BoardResponse::AddEntry(rng.next_u64()))
        }
        2 => {
            Ok(BoardResponse::EditEntry)
        }
        3 => {
            Ok(BoardResponse::GetUser(rand_user(rng, char_rng)))
        }
        4 => {
            Ok(BoardResponse::AddUser(rng.next_u64()))
        }
        _ => panic!("Request Type should be in range")
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
    let mut char_rng = get_char_rng(rng.clone());
    for _ in 0..RANDOM_TEST_RETRIES {
        let user = rand_user(&mut rng, &mut char_rng);
        assert_eq!(user, UserData::from_data(&user.into_data().unwrap()).unwrap(), "Invalid User Conversion");
    }
}

#[test]
fn user_size_hint() {
    let mut rng = rand::rng();
    let mut char_rng = get_char_rng(rng.clone());
    for _ in 0..RANDOM_TEST_RETRIES {
        let user = rand_user(&mut rng, &mut char_rng);
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
    for _ in 0..RANDOM_TEST_RETRIES {
        let response = rand_response(&mut rng, &mut char_rng);
        assert_eq!(response, MaybeBoardResponse::from_data(&MaybeBoardResponse::into_data(&response).unwrap()).unwrap(), "Invalid Request Conversion");
    }
}

#[test]
fn response_size_hint() {
    let mut rng = rand::rng();
    let mut char_rng = get_char_rng(rng.clone());
    for _ in 0..RANDOM_TEST_RETRIES {
        let response = rand_response(&mut rng, &mut char_rng);
        assert_eq!(response.size_hint(), response.into_data().unwrap().len(), "Incorrect size hint");
    }
}

#[test]
fn aead_data_conversion() {
    let mut rng = rand::rng();
    for _ in 0..RANDOM_TEST_RETRIES {
        let key = AeadKey::new_random(&mut rng);
        assert_eq!(key, AeadKey::from_data(&key.into_data().unwrap()).unwrap(), "Invalid AeadKey Converstion");
    }
}


#[test]
fn aead_size_hint() {
    let mut rng = rand::rng();
    for _ in 0..RANDOM_TEST_RETRIES {
        let key = AeadKey::new_random(&mut rng);
        assert_eq!(key.size_hint(), key.into_data().unwrap().len(), "Invalid Size Hint");
    }
}

#[test]
fn aead() {
    let mut rng = rand::rng();
    let mut encrypt_key = AeadKey::new_random(get_sys_rng());
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
#[should_panic]
fn aead_replay_attack() {
    let mut rng = rand::rng();
    let mut encrypt_key = AeadKey::new_random(get_sys_rng());
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
    let _ = decrypt_key.decrypt(nonce, &encrypted, &associated).unwrap(); // <-- should panic here
}

#[test]
#[should_panic]
fn aead_incorrect_nonce() {
    let mut rng = rand::rng();
    let mut encrypt_key = AeadKey::new_random(get_sys_rng());
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
    let _ = decrypt_key.decrypt(nonce+1, &encrypted, &associated).unwrap(); // <-- should panic here
}