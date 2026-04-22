use std::collections::VecDeque;
use std::ops::{Deref, DerefMut};
use std::string::FromUtf8Error;

use crate::cryptography::*;

// this is the 0.6.4 version, vs the 0.10.0 version from the rand crate
use rand_chacha::rand_core::RngCore as OldRngCore;
use rand_chacha::rand_core::CryptoRng as OldCryptoRng; 

pub const PORT: u16 = 8000;
pub const ROOT_ID: u64 = 0x00_00_00_00_00_00_00_00;
pub const ENTRY_MAGIC_NUMBER: u16 = 0x1234;
pub const USER_MAGIC_NUMBER: u16 = 0x1470;

/// file versions
pub const ENTRY_FILE_VERSION: u8 = 0x00;
pub const USER_FILE_VERSION: u8 = 0x00;
pub const REQUEST_FORMAT_VERSION: u8 = 0x00;
pub const RESPONSE_FORMAT_VERSION: u8 = 0x00;

/// file discriminants 
/// General Use
pub const ERROR: u8 = 0xff;
/// Entry
pub const MESSAGE: u8 = 0x00;
pub const ACCESS_GROUP: u8 = 0x01;
/// Request & Response
/// 0x0_ & 0x1_: entry related requests
pub const GET_ENTRY: u8 = 0x00;
pub const ADD_ENTRY: u8 = 0x01;
pub const EDIT_ENTRY: u8 = 0x02;
/// 0x2_ & 0x3_ (?): user related requests
pub const GET_USER: u8 = 0x20;
pub const ADD_USER: u8 = 0x21;
/// 0x8_: network / connection related requests
pub const GET_KEM_EK: u8 = 0x80;
/// encrypted variants
pub const EXPOSED: u8 = 0x00;
pub const FULL_ANON: u8 = 0x01;
pub const USER: u8 = 0x02;

/// access group
pub const INHERIT_BASE: u8 = 0x00;
pub const WHITE_BASE: u8 = 0x01;
pub const BLACK_BASE: u8 = 0x02;


pub mod cryptography;

#[cfg(test)]
pub mod tests;

pub mod utils {
    pub fn stdin_y_n(stdin: &mut std::io::Stdin, buffer: &mut String) -> bool {
    loop {
        let _ = stdin.read_line(buffer);
        *buffer = buffer.trim().to_ascii_lowercase();
        match buffer.as_ref() {
            "y" => return true,
            "n" => return false,
            _ => continue
        }
    }
}
}

pub trait AsData {
    fn extend_data(&self, data: &mut Vec<u8>) -> Result<(), DataError>;
    fn from_data_iter(data_iter: &mut impl Iterator<Item = u8>) -> Result<Self, DataError> where Self: Sized;

    fn size_hint(&self) -> usize {0}
    fn sanitize(&mut self) {}

    fn into_data(&self) -> Result<Vec<u8>, DataError> {
        let mut out= Vec::with_capacity(self.size_hint());
        self.extend_data(&mut out)?;
        Ok(out)
    }

    fn from_data(data: &[u8]) -> Result<Self, DataError> where Self: Sized {
        let mut data_iter = data.iter().copied();
        Self::from_data_iter(&mut data_iter)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum DataError { 
    IncorrectMagicNum,
    InsufficientBytes,
    InvalidDiscriminant,
    StringError(std::string::FromUtf8Error),
    NotHex,
    UnsupportedVersion,

    DoesNotExist,
    AlreadyExists,
    InsufficientPerms,
    BadCredentials,
    MissingKey,
    IncorrectKey,
    EncryptionError,

    MalformedRoot,
    NonChild,
    EdittedLocation,

    InternalError{file: &'static str, line: u32, col: u32},
    OOBUsizeConversion,
}

#[macro_export]
macro_rules! internal_error {
    () => {
        DataError::InternalError{file: file!(), line: line!(), col: column!()}
    };
}

impl From<FromUtf8Error> for DataError {
    fn from(value: FromUtf8Error) -> Self {
        DataError::StringError(value)
    }
}

impl From<aes_gcm::Error> for DataError {
    fn from(_: aes_gcm::Error) -> Self {
        Self::EncryptionError
    }
}

fn read_u8(data_iter: &mut impl Iterator<Item = u8>) -> Result<u8, DataError> {
    data_iter.next().ok_or(DataError::InsufficientBytes)
}

macro_rules! read_num_impls {
    ($($ident:ident: $ty:ty, $size:literal;)*) => {
        $(
            fn $ident(data_iter: &mut impl Iterator<Item = u8>) -> Result<$ty, DataError> {
                read_arr::<$size>(data_iter).map(|x| <$ty>::from_le_bytes(x))
            }
        )*
    };
}

read_num_impls!(
    read_u16: u16, 2;
    read_u32: u32, 4;
    read_u64: u64, 8;
    read_u128: u128, 16;
);

fn read_arr<const U: usize>(data_iter: &mut impl Iterator<Item = u8>) -> Result<[u8; U], DataError> {
    let mut arr = [0; U];
    for i in 0..U {
        arr[i] = read_u8(data_iter)?;
    }
    Ok(arr)
}

#[macro_export]
macro_rules! bounded_usize {
    ($expr:expr, $num:ty) => {
        {
            let val: usize = $expr;
            match (val as $num) as usize == val {
                true => Ok(()),
                false => Err(DataError::OOBUsizeConversion)
            }
        }
    };
}

/// current file version: 0
/// 
/// NOTE: don't forget to update size hints
/// 
/// data format, numbers are little endian: 
///     magic number (u16):         0x1234,   
///     file version number (u8):   00,
///     type (u8):                      
///         Message:                00,   
///         AccessGroup:            01,
///     parent entry id (u64),
///     number of children ids (u16),
///     children id 1 (u64),
///     ...
///     children id n (u64),
///     author id (u64),
///     remaining is dependent on the type
/// 
/// Message:
///     timestamp (secs since Unix Epoch) (u64),
///     message size (u32),
///     remaining [message size] bytes are the message which is a utf8 encoded string
/// 
/// AccessGroup:
///     group name length (u32),
///     group name string (utf8 encoded),
///     write perms: DefaultedIdSet
///     read perms: DefaultedIdSet
/// 
/// 
#[derive(PartialEq, Eq, Debug)]
pub struct Entry {
    pub header_data: HeaderData,
    pub entry_data: EntryData,
}

impl AsData for Entry {
    fn from_data_iter(data_iter: &mut impl Iterator<Item = u8>) -> Result<Self, DataError> {
        let (header_data, entry_type) = HeaderData::from_data_iter(data_iter)?;
        let entry_data = EntryData::from_data_iter(data_iter, entry_type)?;
        Ok(Entry {
            header_data,
            entry_data,
        })
    }

    fn extend_data(&self, data: &mut Vec<u8>) -> Result<(), DataError> {
        self.header_data.extend_data(self.entry_data.get_discriminant(), data)?;
        self.entry_data.extend_data(data)?;
        Ok(())
    }

    fn size_hint(&self) -> usize {
        self.header_data.size_hint() + self.entry_data.size_hint()
    }
}

#[derive(PartialEq, Eq, Debug)]
pub struct HeaderData {
    pub version: u8,
    pub parent_id: u64,
    pub children_ids: Vec<u64>,
    pub author_id: u64,
}

impl HeaderData {
    /// gives a HeaderData and the entry type
    pub fn from_data(data: &[u8]) -> Result<(Self, u8), DataError> {
        let mut data_iter = data.iter().copied();
        HeaderData::from_data_iter(&mut data_iter)
    }

    /// gives a HeaderData and the entry type
    pub fn from_data_iter(data_iter: &mut impl Iterator<Item = u8>) -> Result<(Self, u8), DataError> {
        let magic_number = read_u16(data_iter)?;
        if magic_number != ENTRY_MAGIC_NUMBER {return Err(DataError::IncorrectMagicNum)}

        let version = read_u8(data_iter)?;
        if version != 0 {return Err(DataError::UnsupportedVersion)}

        let entry_type = read_u8(data_iter)?;

        let parent_id = read_u64(data_iter)?;
        let num_children = read_u16(data_iter)?;
        let mut children_ids = Vec::new();
        for _ in 0..num_children {
            children_ids.push(read_u64(data_iter)?);
        }

        let author_id = read_u64(data_iter)?;
        Ok((HeaderData { version, parent_id, children_ids, author_id }, entry_type))
    }

    pub fn into_data(&self, entry_type: u8) -> Result<Vec<u8>, DataError> {
        let mut data = Vec::new();
        self.extend_data(entry_type, &mut data)?;
        Ok(data)
    }

    pub fn extend_data(&self, entry_type: u8, data: &mut Vec<u8>) -> Result<(), DataError> {
        data.extend_from_slice(&ENTRY_MAGIC_NUMBER.to_le_bytes());
        data.push(ENTRY_FILE_VERSION);
        data.push(entry_type);
        data.extend_from_slice(&self.parent_id.to_le_bytes());
        bounded_usize!(self.children_ids.len(), u16)?;
        data.extend_from_slice(&(self.children_ids.len() as u16).to_le_bytes());
        data.extend(self.children_ids.iter().flat_map(|x| x.to_le_bytes()));
        data.extend_from_slice(&self.author_id.to_le_bytes());
        Ok(())
    }

    pub fn size_hint(&self) -> usize {
        2 + 1 + 1 + 8 + 2 + self.children_ids.len() * 8 + 8
    }
}

#[derive(PartialEq, Eq, Debug)]
pub enum DefaultBase {
    Inherit,
    White,
    Black,
}

impl DefaultBase {
    pub fn get_discriminant(&self) -> u8 {
        match self {
            Self::Inherit => INHERIT_BASE,
            Self::White => WHITE_BASE,
            Self::Black => BLACK_BASE,
        }
    }

    pub fn from_discriminant(discriminant: u8) -> Result<Self, DataError> {
        match discriminant {
            INHERIT_BASE => Ok(Self::Inherit),
            WHITE_BASE => Ok(Self::White),
            BLACK_BASE => Ok(Self::Black),
            _ => Err(DataError::InvalidDiscriminant)
        }
    }
}

impl std::fmt::Display for DefaultBase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", match self {
            Self::Inherit => "Inherit",
            Self::Black => "Black",
            Self::White => "White",
        })
    }
}

/// data format:
/// 
/// DefaultBase discriminant (u8)
/// Rest depends on the DefaultBase
/// 
/// Inherit:
///     number of whitelist_ids (u32)
///     whitelisted id 1 - n (u64 each)
///     number of blacklist_ids (u32)
///     blacklisted id 1 - n (u64 each)
/// 
/// Black:
///     number of whitelist_ids (u32)
///     whitelisted id 1 - n (u64 each)
/// 
/// White:
///     number of blacklist_ids (u32)
///     blacklisted id 1 - n (u64 each)
#[derive(PartialEq, Eq, Debug)]
pub enum DefaultedIdSet {
    Inherit{whitelist_ids: Vec<u64>, blacklist_ids: Vec<u64>},
    White{blacklist_ids: Vec<u64>},
    Black{whitelist_ids: Vec<u64>},
}

impl DefaultedIdSet {
    pub fn contains(&self, id: u64) -> Option<bool> {
        match self {
            Self::Inherit { whitelist_ids, blacklist_ids } => {
                let whitelisted = whitelist_ids.contains(&id);
                let blacklisted = blacklist_ids.contains(&id);
                match (whitelisted, blacklisted) {
                    (true, false) => Some(true),
                    (false, true) => Some(false),
                    _ => None
                }
            }
            Self::White { blacklist_ids } => {
                Some(!blacklist_ids.contains(&id))
            }
            Self::Black { whitelist_ids } => {
                Some(whitelist_ids.contains(&id))
            }
        }
    }

    pub fn get_default_base(&self) -> DefaultBase {
        match &self {
            Self::Inherit { whitelist_ids: _, blacklist_ids: _ } => DefaultBase::Inherit,
            Self::Black { whitelist_ids: _ } => DefaultBase::Black,
            Self::White { blacklist_ids: _ } => DefaultBase::White,
        }
    }
}

impl AsData for DefaultedIdSet {
    fn from_data_iter(data_iter: &mut impl Iterator<Item = u8>) -> Result<Self, DataError> {
        fn read_vec(data_iter: &mut impl Iterator<Item = u8>) -> Result<Vec<u64>, DataError> {
            let len = read_u32(data_iter)? as usize;
            let mut vec = Vec::with_capacity(len);
            for _ in 0..len {
                vec.push(read_u64(data_iter)?);
            }
            Ok(vec)
        }

        Ok(match DefaultBase::from_discriminant(read_u8(data_iter)?)? {
            DefaultBase::Inherit => {
                let whitelist_ids = read_vec(data_iter)?;
                let blacklist_ids = read_vec(data_iter)?;
                Self::Inherit { whitelist_ids, blacklist_ids }
            }
            DefaultBase::White => {
                let blacklist_ids = read_vec(data_iter)?;
                Self::White { blacklist_ids }
            }
            DefaultBase::Black => {
                let whitelist_ids = read_vec(data_iter)?;
                Self::Black { whitelist_ids }
            }
        })
    }

    fn extend_data(&self, data: &mut Vec<u8>) -> Result<(), DataError> {
        fn write_vec(vec: &[u64], data: &mut Vec<u8>) -> Result<(), DataError> {
            bounded_usize!(vec.len(), u32)?;
            data.extend_from_slice(&(vec.len() as u32).to_le_bytes());
            data.extend(vec.iter().flat_map(|x| x.to_le_bytes()));
            Ok(())
        }

        data.push(self.get_default_base().get_discriminant());
        match self {
            Self::Inherit { whitelist_ids, blacklist_ids } => {
                write_vec(&whitelist_ids, data)?;
                write_vec(&blacklist_ids, data)?;
            }
            Self::White { blacklist_ids } => {
                write_vec(&blacklist_ids, data)?;
            }
            Self::Black { whitelist_ids } => {
                write_vec(&whitelist_ids, data)?;
            }
        }
        Ok(())
    }

    fn size_hint(&self) -> usize {
        match self {
            DefaultedIdSet::Inherit { whitelist_ids, blacklist_ids } => {
                1 + 4 + whitelist_ids.len() * 8 + 4 + blacklist_ids.len() * 8
            }
            DefaultedIdSet::Black { whitelist_ids } => {
                1 + 4 + whitelist_ids.len() * 8
            }
            DefaultedIdSet::White { blacklist_ids } => {
                1 + 4 + blacklist_ids.len() * 8
            }
        }
    }
}

#[derive(PartialEq, Eq, Debug)]
pub enum EntryData {
    Message {
        timestamp: u64,
        message: String,
    },
    AccessGroup {
        name: String,
        write_perms: DefaultedIdSet,
        read_perms: DefaultedIdSet,
    },
}

impl EntryData {
    pub fn get_discriminant(&self) -> u8 {
        match self {
            Self::Message { timestamp: _, message: _ } => MESSAGE,
            Self::AccessGroup { name: _, read_perms: _, write_perms: _ } => ACCESS_GROUP,
        }
    }

    pub fn from_data_iter(data_iter: &mut impl Iterator<Item = u8>, entry_type: u8) -> Result<Self, DataError> {
        Ok(match entry_type {
            MESSAGE => { // Message
                let timestamp = read_u64(data_iter)?;
                let message_size = read_u32(data_iter)? as usize;
                let message = String::from_utf8(data_iter.take(message_size).collect::<Vec<_>>()).map_err(|e| DataError::StringError(e))?;
                //if message.len() != message_size {return Err(DataError::MessageError)}
                EntryData::Message { timestamp, message }
            }
            ACCESS_GROUP => { // AccessGroup
                let name_len = read_u32(data_iter)? as usize;
                let name = String::from_utf8((data_iter).take(name_len).collect::<Vec<_>>()).map_err(|e| DataError::StringError(e))?;
                let write_perms = DefaultedIdSet::from_data_iter(data_iter)?;
                let read_perms = DefaultedIdSet::from_data_iter(data_iter)?;
                EntryData::AccessGroup { name, write_perms, read_perms }
            }
            _ => {return Err(DataError::InvalidDiscriminant)}
        })
    }

    pub fn extend_data(&self, data: &mut Vec<u8>) -> Result<(), DataError> {
        match self {
            Self::Message { timestamp, message } => {
                data.extend_from_slice(&timestamp.to_le_bytes());
                bounded_usize!(message.len(), u32)?;
                data.extend_from_slice(&(message.len() as u32).to_le_bytes());
                data.extend_from_slice(message.as_bytes());
            }
            Self::AccessGroup { name, write_perms, read_perms } => {
                bounded_usize!(name.len(), u32)?;
                data.extend_from_slice(&(name.len() as u32).to_le_bytes());
                data.extend_from_slice(name.as_bytes());
                write_perms.extend_data(data)?;
                read_perms.extend_data(data)?;
            }
        }
        Ok(())
    }

    pub fn size_hint(&self) -> usize {
        match self {
            EntryData::Message { message, .. } => {
                8 + 4 + message.as_bytes().len()
            }
            EntryData::AccessGroup { name, write_perms, read_perms } => {
                4 + name.as_bytes().len() + write_perms.size_hint() + read_perms.size_hint()
            }
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum EntryVariant {
    Message,
    AccessGroup,
}

impl EntryVariant {
    pub fn as_string(self) -> &'static str {
        match self {
            Self::Message => "Message",
            Self::AccessGroup => "Access Group"
        }
    }
}

#[derive(PartialEq, Eq, Debug)]
pub struct UserData {
    pub aead: UserAeadKey,
    pub entry_ids: Vec<u64>,
}

impl UserData {
    pub fn new_empty(key: UserAeadKey) -> Self {
        UserData { 
            aead: key,
            entry_ids: Vec::new() ,
        }
    }
}

/// currrent file version 0
/// 
/// data format, numbers are little endian:
///     magic number (u16): see `USER_MAGIC_NUMBER`
///     version number (u8)
///     - UserAeadKey data - 
///     number of entry ids (u32),
///     entry id 1 (u64),
///     ...
///     entry id n (u64)
impl AsData for UserData {
    fn from_data_iter(data_iter: &mut impl Iterator<Item = u8>) -> Result<Self, DataError> {
        let magic_number = read_u16(data_iter)?;
        if magic_number != USER_MAGIC_NUMBER {return Err(DataError::IncorrectMagicNum)};
        let version = read_u8(data_iter)?;
        if version != 0 {return Err(DataError::UnsupportedVersion)};
        let aead = UserAeadKey::from_data_iter(data_iter)?;
        let num_entries = read_u32(data_iter)? as usize;
        let mut entry_ids = Vec::with_capacity(num_entries);
        for _ in 0..num_entries {
            entry_ids.push(read_u64(data_iter)?);
        }
        Ok(UserData { 
            aead,
            entry_ids
        })
    }

    fn extend_data(&self, data: &mut Vec<u8>) -> Result<(), DataError> {
        data.extend_from_slice(&USER_MAGIC_NUMBER.to_le_bytes());
        data.push(USER_FILE_VERSION);
        self.aead.extend_data(data)?;
        bounded_usize!(self.entry_ids.len(), u32)?;
        data.extend_from_slice(&(self.entry_ids.len() as u32).to_le_bytes());
        data.extend(self.entry_ids.iter().flat_map(|x| x.to_le_bytes()));
        Ok(())
    }

    fn size_hint(&self) -> usize {
        2 + 1 + 4 + self.entry_ids.len() * 8
    }
    fn sanitize(&mut self) {
        self.aead.sanitize();
    }
}

#[derive(Debug)]
pub struct PublicKeySet {
    pub kem: Option<EncapsulationKey>,
    pub simple_aead: VecDeque<SimpleAeadKey>, // not stored in data
    pub user_aead: Option<UserAeadKey>,
}

impl PublicKeySet {
    pub fn new(kem: Option<EncapsulationKey>, user_aead: Option<UserAeadKey>) -> Self {
        Self { kem, simple_aead: VecDeque::new(), user_aead }
    } 
}

impl AsData for PublicKeySet {
    fn size_hint(&self) -> usize {
        1 + self.kem.as_ref().map_or(0, |x| x.size_hint())+ self.user_aead.as_ref().map_or(0, |x| x.size_hint())
    }

    fn from_data_iter(data_iter: &mut impl Iterator<Item = u8>) -> Result<Self, DataError> where Self: Sized {
        let option_bools = read_u8(data_iter)?;
        let has_kem = (option_bools & 0b01) != 0;
        let has_user_aead = (option_bools & 0b10) != 0;
        let mut kem = None;
        if has_kem {
            kem = Some(EncapsulationKey::from_data_iter(data_iter)?);
        }
        let mut user_aead = None;
        if has_user_aead {
            user_aead = Some(UserAeadKey::from_data_iter(data_iter)?);
        }
        Ok(Self::new(kem, user_aead))
    }

    fn extend_data(&self, data: &mut Vec<u8>) -> Result<(), DataError> {
        data.push((self.kem.is_some() as u8) | ((self.user_aead.is_some() as u8) << 1));
        if let Some(kem) = self.kem.as_ref() {
            kem.extend_data(data)?;
        }
        if let Some(aead) = self.user_aead.as_ref() {
            aead.extend_data(data)?;
        }
        Ok(())
    }
}

pub enum ReEncryptionData {
    Exposed,
    FullAnonymous(SimpleAeadKey),
    User(u64),
}

/// data format:
///     version (u8): 00
///     variant discriminant (u8) (listed with each variant)
///     - variant specific data -
/// 
/// GetEntry, 0x00:
///     user_id (u64)
///     entry_id (u64)
/// 
/// AddEntry, 0x01:
///     user_id (u64)
///     - Entry data - 
/// 
/// EditEntry, 0x03:
///     user_id (u64),
///     entry_id (u64)
///     - Entry data -
/// 
/// GetUser, 0x20:
///     user_id (u64)
/// 
/// AddUser, 0x21:
///     - no data -
#[derive(PartialEq, Eq, Debug)]
pub enum BoardRequest {
    GetEntry { user_id: u64, entry_id: u64 },
    AddEntry { user_id: u64, entry: Entry },
    EditEntry { user_id: u64, entry_id: u64, entry: Entry },
    GetUser { user_id: u64 },
    AddUser,
    GetKemEk,
}

impl AsData for BoardRequest {
    fn extend_data(&self, data: &mut Vec<u8>) -> Result<(), DataError> {
        data.push(REQUEST_FORMAT_VERSION); //version
        match self {
            BoardRequest::GetEntry { user_id, entry_id } => {
                data.push(GET_ENTRY);
                data.extend_from_slice(&user_id.to_le_bytes());
                data.extend_from_slice(&entry_id.to_le_bytes());
            },
            BoardRequest::AddEntry { user_id, entry } => {
                data.push(ADD_ENTRY);
                data.extend_from_slice(&user_id.to_le_bytes());
                entry.extend_data(data)?;
            },
            BoardRequest::EditEntry { user_id, entry_id, entry } => {
                data.push(EDIT_ENTRY);
                data.extend_from_slice(&user_id.to_le_bytes());
                data.extend_from_slice(&entry_id.to_le_bytes());
                entry.extend_data(data)?;
            }
            BoardRequest::GetUser { user_id } => {
                data.push(GET_USER);
                data.extend_from_slice(&user_id.to_le_bytes());
            },
            BoardRequest::AddUser => data.push(ADD_USER),
            BoardRequest::GetKemEk => data.push(GET_KEM_EK)
        };
        Ok(())
    }

    fn from_data_iter(data_iter: &mut impl Iterator<Item = u8>) -> Result<Self, DataError> where Self: Sized {
        let version = read_u8(data_iter)?;
        if version != 0x00 {return Err(DataError::UnsupportedVersion)};
        let discriminant = read_u8(data_iter)?;
        Ok(match discriminant {
            // entry requests
            GET_ENTRY => { // GetEntry
                let user_id = read_u64(data_iter)?;
                let entry_id = read_u64(data_iter)?;
                BoardRequest::GetEntry { user_id, entry_id }
            }
            ADD_ENTRY => { // AddEntry
                let user_id = read_u64(data_iter)?;
                let entry = Entry::from_data_iter(data_iter)?;
                BoardRequest::AddEntry { user_id, entry }
            }
            EDIT_ENTRY => {
                let user_id = read_u64(data_iter)?;
                let entry_id = read_u64(data_iter)?;
                let entry = Entry::from_data_iter(data_iter)?;
                BoardRequest::EditEntry { user_id, entry_id, entry }
            }
            // user requests
            GET_USER => { // GetUser
                let user_id = read_u64(data_iter)?;
                BoardRequest::GetUser { user_id }
            }
            ADD_USER => { // AddUser
                BoardRequest::AddUser
            }
            // network requests
            GET_KEM_EK => {
                BoardRequest::GetKemEk
            }
            _ => {return Err(DataError::InvalidDiscriminant)}
        })
    }

    fn size_hint(&self) -> usize {
        match self {
            BoardRequest::GetEntry { .. } => {
                1 + 1 + 8 + 8
            }
            BoardRequest::AddEntry { entry, .. } => {
                1 + 1 + 8 + entry.size_hint()
            }
            BoardRequest::EditEntry { entry, .. } => {
                1 + 1 + 8 + 8 + entry.size_hint()
            }
            BoardRequest::GetUser { .. } => {
                1 + 1 + 8
            }
            BoardRequest::AddUser => {
                1 + 1
            }
            BoardRequest::GetKemEk => {
                1 + 1
            }
        }
    }
}

/// secure data format:
///     version (u8): 00
///     kem header varient (u8): 
///     kem section: (will default to full anonymous when possible)
///         0x00, exposed (the following data is not encrypted at all)
///         0x01, full anonymous (raw kem):
///             RawCipherText which yields 
///                 256 bit aead key 
///                 nonce is assumed 0
///         0x02, user (using my kem wrapper):
///             KemCipherText which yields:
///                 user_id (u64) (mapped by server to that user's UserAeadKey)
///                 nonce (u128) (not the true nonce, a counter fed into an rng to get the real nonce)
///     aead section (or plaintext if the exposed kem variant):
///         variant discriminant (u8) (listed with each variant)
///         - variant specific data -
/// 
/// GetEntry, 0x00 (user):
///     entry_id (u64)
/// 
/// AddEntry, 0x01 (user):
///     - Entry data - 
/// 
/// EditEntry, 0x03 (user): 
///     entry_id (u64)
///     - Entry data -
/// 
/// GetUser, 0x20 (any):
///     user_id (u64)
/// 
/// AddUser, 0x21 (any):
///     - no data -
impl BoardRequest {
    pub fn secure_extend_data(&self, rng: impl OldCryptoRng + OldRngCore, keys: &mut PublicKeySet, data: &mut Vec<u8>) -> Result<(), DataError> {
        data.push(REQUEST_FORMAT_VERSION); //version
        let mut body = Vec::new();
        match self {
            // todo: change Vec::new's into Vec::with_capacity
            BoardRequest::GetEntry { entry_id, .. } => {
                body.push(GET_ENTRY);
                body.extend_from_slice(&entry_id.to_le_bytes());
            },
            BoardRequest::AddEntry { entry, .. } => {
                body.push(ADD_ENTRY);
                entry.extend_data(&mut body)?;
            },
            BoardRequest::EditEntry { entry_id, entry, .. } => {
                body.push(EDIT_ENTRY);
                body.extend_from_slice(&entry_id.to_le_bytes());
                entry.extend_data(&mut body)?;
            }
            BoardRequest::GetUser { user_id } => {
                body.push(GET_USER);
                body.extend_from_slice(&user_id.to_le_bytes());
            },
            BoardRequest::AddUser => body.push(ADD_USER),
            BoardRequest::GetKemEk => body.push(GET_KEM_EK)
        };
        match self {
            BoardRequest::GetEntry { user_id, .. } | BoardRequest::AddEntry { user_id, ..} | BoardRequest::EditEntry { user_id, .. } => {
                data.push(USER);
                extend_with_user_block(rng, keys, *user_id, data, &mut body)?;
            }
            BoardRequest::GetUser { .. } | BoardRequest::AddUser { .. } if keys.kem.is_some() => {
                data.push(FULL_ANON);
                let simple_aead = extend_with_full_anonymous_block(rng, keys, data, &mut body)?;
                keys.simple_aead.push_back(simple_aead);
            }
            _ => {
                data.push(EXPOSED);
                extend_with_exposed_block(data, &mut body)?;
            }
        }
        Ok(())
    }

    pub fn secure_into_data(&self, rng: impl OldCryptoRng + OldRngCore, keys: &mut PublicKeySet) -> Result<Vec<u8>, DataError> {
        let mut out = Vec::new();
        self.secure_extend_data(rng, keys, &mut out)?;
        Ok(out)
    }

    pub fn secure_from_data_iter<'a, F: FnOnce(u64) -> Option<T>, T: Deref<Target = UserAeadKey> + DerefMut>(kem_dk: &DecapsulationKey, get_user_aead: F, data_iter: &mut impl Iterator<Item = u8>) -> Result<(ReEncryptionData, Self), DataError> {
        if read_u8(data_iter)? != REQUEST_FORMAT_VERSION {return Err(DataError::UnsupportedVersion)}
        let mut user_id = None;
        let (re_encryptor, body) = match read_u8(data_iter)? {
            EXPOSED => {
                let body = read_from_exposed_block(data_iter)?.collect();
                (ReEncryptionData::Exposed, body)
            },
            FULL_ANON => {
                let (data, body) = read_from_full_anonymous_block(kem_dk, data_iter)?;
                (ReEncryptionData::FullAnonymous(data), body)
            },
            USER => {
                let (user, body) = read_from_user_block(kem_dk, data_iter, get_user_aead)?;
                user_id = Some(user);
                (ReEncryptionData::User(user), body)
            }
            _ => {return Err(DataError::InvalidDiscriminant)}
        };
        let mut body = body.into_iter();
        let discriminant = read_u8(&mut body)?;
        Ok((re_encryptor, match discriminant {
            // entry requests
            GET_ENTRY => { // GetEntry
                let entry_id = read_u64(&mut body)?;
                BoardRequest::GetEntry { user_id: user_id.unwrap(), entry_id }
            }
            ADD_ENTRY => { // AddEntry
                let entry = Entry::from_data_iter(&mut body)?;
                BoardRequest::AddEntry { user_id: user_id.unwrap(), entry }
            }
            EDIT_ENTRY => {
                let entry_id = read_u64(&mut body)?;
                let entry = Entry::from_data_iter(&mut body)?;
                BoardRequest::EditEntry { user_id: user_id.unwrap(), entry_id, entry }
            }
            // user requests
            GET_USER => { // GetUser
                let user_id = read_u64(&mut body)?;
                BoardRequest::GetUser { user_id }
            }
            ADD_USER => { // AddUser
                BoardRequest::AddUser
            }
            // network requests
            GET_KEM_EK => {
                BoardRequest::GetKemEk
            }
            _ => {return Err(DataError::InvalidDiscriminant)}
        }))
    }

    pub fn secure_from_data<'a, F: FnOnce(u64) -> Option<T>, T: Deref<Target = UserAeadKey> + DerefMut>(kem_dk: &DecapsulationKey, get_user_aead: F, data: &[u8]) -> Result<(ReEncryptionData, Self), DataError> {
        Self::secure_from_data_iter(kem_dk, get_user_aead, &mut data.into_iter().copied())
    }
}

/// the response 
#[derive(PartialEq, Debug)]
pub enum BoardResponse {
    GetEntry(Entry),
    AddEntry(u64),
    EditEntry,

    GetUser(UserData),
    AddUser{user_id: u64, user_aead: UserAeadKey},

    GetKemEk(EncapsulationKey),
    
    Error(DataError),
}

pub type MaybeBoardResponse = Result<BoardResponse, DataError>;

impl BoardResponse {
    pub fn encapsulate_error(val: MaybeBoardResponse) -> Self {
        match val {
            Err(e) => Self::Error(e),
            Ok(v) => v
        }
    }
}

/// data format:
///     version (u8): 0
///     variant discriminant (u8) (listed with each variant)
/// 
/// GetEntry, 0x00:
///     - Entry Data -
/// 
/// AddEntry, 0x01:
///     entry_id (u64)
/// 
/// EditEntry, 0x02:
///     - no data -
/// 
/// GetUser, 0x20:
///     - User Data -
/// 
/// AddUser, 0x21:
///     user_id (u64)
/// 
/// Error, 0xff:
///     - no data - 
impl AsData for BoardResponse {
    fn extend_data(&self, data: &mut Vec<u8>) -> Result<(), DataError> {
        data.push(RESPONSE_FORMAT_VERSION);
        match self {
            BoardResponse::GetEntry(entry) => {
                data.push(GET_ENTRY);
                entry.extend_data(data)?;
            }
            BoardResponse::AddEntry(entry_id) => {
                data.push(ADD_ENTRY);
                data.extend_from_slice(&entry_id.to_le_bytes());
            }
            BoardResponse::EditEntry => {
                data.push(EDIT_ENTRY);
            }
            BoardResponse::GetUser(user) => {
                data.push(GET_USER);
                user.extend_data(data)?;
            }
            BoardResponse::AddUser{user_id, user_aead} => {
                data.push(ADD_USER);
                data.extend_from_slice(&user_id.to_le_bytes());
                user_aead.extend_data(data)?;
            }
            BoardResponse::GetKemEk(kem_ek) => {
                data.push(GET_KEM_EK);
                kem_ek.extend_data(data)?;
            }
            BoardResponse::Error(e) => { // TODO: should consider the error
                eprintln!("Sending Error: {:?}", e);
                data.push(ERROR);
            }
        }
        Ok(())
    }

    fn from_data_iter(data_iter: &mut impl Iterator<Item = u8>) -> Result<Self, DataError> where Self: Sized {
        let version = read_u8(data_iter)?;
        if version != 0 {return Err(DataError::UnsupportedVersion)}
        Ok(match read_u8(data_iter)? {
            // entry requests
            GET_ENTRY => { // GetEntry
                let entry = Entry::from_data_iter(data_iter)?;
                BoardResponse::GetEntry(entry)
            }
            ADD_ENTRY => { // AddEntry
                let entry_id = read_u64(data_iter)?;
                BoardResponse::AddEntry(entry_id)
            }
            EDIT_ENTRY => BoardResponse::EditEntry,
            // user requests
            GET_USER => { // GetUser
                let user = UserData::from_data_iter(data_iter)?;
                BoardResponse::GetUser(user)
            }
            ADD_USER => { // AddUser
                let user_id = read_u64(data_iter)?;
                let user_aead = UserAeadKey::from_data_iter(data_iter)?;
                BoardResponse::AddUser{user_id, user_aead}
            }
            // network responses
            GET_KEM_EK => {
                let kem_ek = EncapsulationKey::from_data_iter(data_iter)?;
                BoardResponse::GetKemEk(kem_ek)
            }
            ERROR => {
                BoardResponse::Error(internal_error!()) //not really an internal error, it just isn't encoded atm
            }
            _ => {return Err(DataError::InvalidDiscriminant)}
        })
    }

    fn size_hint(&self) -> usize {
        match self {
            BoardResponse::GetEntry(entry) => {
                1 + 1 + entry.size_hint()
            }
            BoardResponse::AddEntry(_) => {
                1 + 1 + 8
            }
            BoardResponse::EditEntry => {
                1 + 1
            }
            BoardResponse::GetUser(user) => {
                1 + 1 + user.size_hint()
            }
            BoardResponse::AddUser{user_id: _, user_aead } => {
                1 + 1 + 8 + user_aead.size_hint()
            }
            BoardResponse::GetKemEk(kem_ek) =>{
                1 + 1 + kem_ek.size_hint()
            }
            BoardResponse::Error(_) => {
                1 + 1
            }
        }
    }
}

/// secure data format:
///     version (u8): 0
///     encryption discriminant:
///     encrypted body
/// 
/// Body:
///     variant discriminant (u8) (listed with each variant)
///     - variant data - 
/// 
/// GetEntry, 0x00:
///     - Entry Data -
/// 
/// AddEntry, 0x01:
///     entry_id (u64)
/// 
/// EditEntry, 0x02:
///     - no data -
/// 
/// GetUser, 0x20:
///     - User Data -
/// 
/// AddUser, 0x21:
///     user_id (u64)
/// 
/// Error, 0xff:
///     - no data - 
impl BoardResponse {
    pub fn secure_extend_data<'a, F: FnOnce(u64) -> Option<T>, T: Deref<Target = UserAeadKey> + DerefMut>(&self, rng: impl OldCryptoRng + OldRngCore, re_encryptor: ReEncryptionData, data: &mut Vec<u8>, get_user_aead: F) -> Result<(), DataError> {
        data.push(RESPONSE_FORMAT_VERSION);
        let mut body = Vec::new();
        match self {
            BoardResponse::GetEntry(entry) => {
                body.push(GET_ENTRY);
                entry.extend_data(&mut body)?;
            }
            BoardResponse::AddEntry(entry_id) => {
                body.push(ADD_ENTRY);
                body.extend_from_slice(&entry_id.to_le_bytes());
            }
            BoardResponse::EditEntry => {
                body.push(EDIT_ENTRY);
            }
            BoardResponse::GetUser(user) => {
                body.push(GET_USER);
                user.extend_data(&mut body)?;
            }
            BoardResponse::AddUser{user_id, user_aead} => {
                body.push(ADD_USER);
                body.extend_from_slice(&user_id.to_le_bytes());
                user_aead.extend_data(&mut body)?;
            }
            BoardResponse::GetKemEk(kem_ek) => {
                body.push(GET_KEM_EK);
                kem_ek.extend_data(&mut body)?;
            }
            BoardResponse::Error(e) => { // TODO: should consider the error
                eprintln!("Sending Error: {:?}", e);
                body.push(ERROR);
            }
        }
        match re_encryptor {
            ReEncryptionData::Exposed => {
                data.push(EXPOSED);
                extend_with_exposed_block(data, &body)?;
            }
            ReEncryptionData::FullAnonymous(key) => {
                data.push(FULL_ANON);
                extend_with_full_anonymous_response_block(&key, data, &body)?;
            }
            ReEncryptionData::User(user_id) => {
                data.push(USER);
                let mut aead = get_user_aead(user_id).map_or(Err(DataError::MissingKey), |x| Ok(x))?;
                extend_with_user_response_block(rng, &mut *aead, data, &body)?;
            }
        }
        Ok(())
    }

    pub fn secure_into_data<'a, F: FnOnce(u64) -> Option<T>, T: Deref<Target = UserAeadKey> + DerefMut>(&self, rng: impl OldCryptoRng + OldRngCore, re_encryptor: ReEncryptionData, get_user_aead: F) -> Result<Vec<u8>, DataError> {
        let mut out = Vec::new();
        self.secure_extend_data(rng, re_encryptor, &mut out, get_user_aead)?;
        Ok(out)
    }

    pub fn secure_from_data_iter(data_iter: &mut impl Iterator<Item = u8>, keys: &mut PublicKeySet) -> Result<Self, DataError> {
        let version = read_u8(data_iter)?;
        if version != 0 {return Err(DataError::UnsupportedVersion)}
        let mut body = match read_u8(data_iter)? {
            EXPOSED => {
                read_from_exposed_block(data_iter)?.collect::<Vec<_>>()
            }
            FULL_ANON => {
                let (true_key, body) = read_from_full_anonymous_response_block(keys.simple_aead.iter(), data_iter)?;
                let mut true_key_idx = 0;
                for (key_idx, key) in keys.simple_aead.iter().enumerate() {
                    if key == true_key {true_key_idx = key_idx; break;}
                }
                keys.simple_aead.remove(true_key_idx);
                body
            }
            USER => {
                let Some(user_aead) = &mut keys.user_aead else {return Err(DataError::MissingKey)};
                read_from_user_response_block(user_aead, data_iter)?
            }
            _ => {return Err(DataError::InvalidDiscriminant)}
        }.into_iter();
        Ok(match read_u8(&mut body)? {
            // entry responses
            GET_ENTRY => { // GetEntry
                let entry = Entry::from_data_iter(&mut body)?;
                BoardResponse::GetEntry(entry)
            }
            ADD_ENTRY => { // AddEntry
                let entry_id = read_u64(&mut body)?;
                BoardResponse::AddEntry(entry_id)
            }
            EDIT_ENTRY => BoardResponse::EditEntry,
            // user responses
            GET_USER => { // GetUser
                let user = UserData::from_data_iter(&mut body)?;
                BoardResponse::GetUser(user)
            }
            ADD_USER => { // AddUser
                let user_id = read_u64(&mut body)?;
                let user_aead = UserAeadKey::from_data_iter(&mut body)?;
                BoardResponse::AddUser{user_id, user_aead}
            }
            // network responses
            GET_KEM_EK => {
                let kem_ek = EncapsulationKey::from_data_iter(&mut body)?;
                BoardResponse::GetKemEk(kem_ek)
            }
            ERROR => {
                BoardResponse::Error(internal_error!()) //not really an internal error, it just isn't encoded atm
            }
            _ => {return Err(DataError::InvalidDiscriminant)}
        })
    }

    pub fn secure_from_data(data: &[u8], keys: &mut PublicKeySet) -> Result<Self, DataError> {
        Self::secure_from_data_iter(&mut data.iter().copied(), keys)
    }
}