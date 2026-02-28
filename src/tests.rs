use rand::{distr::Distribution, Rng};

use crate::*;

const RANDOM_TEST_RETRIES: usize = 100;
const RANDOM_CHAR_RANGE: std::ops::Range<char> = '\u{0000}'..'\u{10ff}';

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
    let request = match rng.random_range(0..4) {
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
            BoardRequest::GetUser { user_id }
        }
        3 => {
            BoardRequest::AddUser
        }
        _ => panic!("Request Type should be in range")
    };
    request
}

fn rand_response(mut rng: impl Rng, char_rng: impl Iterator<Item = char>) -> MaybeBoardResponse {
    match rng.random_range(0..4) {
        0 => {
            Ok(BoardResponse::GetEntry(rand_entry(rng, char_rng)))
        }
        1 => {
            Ok(BoardResponse::AddEntry(rng.next_u64()))
        }
        2 => {
            Ok(BoardResponse::GetUser(rand_user(rng, char_rng)))
        }
        3 => {
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
fn user_data_conversion() {
    let mut rng = rand::rng();
    let mut char_rng = get_char_rng(rng.clone());
    for _ in 0..RANDOM_TEST_RETRIES {
        let user = rand_user(&mut rng, &mut char_rng);
        assert_eq!(user, UserData::from_data(&user.into_data().unwrap()).unwrap(), "Invalid User Conversion");
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
fn response_data_conversion() {
    let mut rng = rand::rng();
    let mut char_rng = get_char_rng(rng.clone());
    for _ in 0..RANDOM_TEST_RETRIES {
        let response = rand_response(&mut rng, &mut char_rng);
        assert_eq!(response, BoardResponse::from_data(&BoardResponse::into_data(&response).unwrap()), "Invalid Request Conversion");
    }
}