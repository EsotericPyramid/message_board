use std::string::FromUtf8Error;

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
pub const GET_ENTRY: u8 = 0x00;
pub const ADD_ENTRY: u8 = 0x01;
pub const GET_USER: u8 = 0x20;
pub const ADD_USER: u8 = 0x21;

/// access group
pub const INHERIT_BASE: u8 = 0x00;
pub const WHITE_BASE: u8 = 0x01;
pub const BLACK_BASE: u8 = 0x02;

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

#[derive(Debug, PartialEq, Eq)]
pub enum DataError { 
    IncorrectMagicNum,
    InsufficientBytes,
    InvalidDiscriminant,
    StringError(std::string::FromUtf8Error),
    UnsupportedVersion,

    DoesNotExist,
    AlreadyExists,
    InsufficientPerms,
    BadCredentials,

    MalformedRoot,
    NonChild,

    InternalError,
    OOBUsizeConversion,
}

impl From<FromUtf8Error> for DataError {
    fn from(value: FromUtf8Error) -> Self {
        DataError::StringError(value)
    }
}

fn read_u16(data_iter: &mut impl Iterator<Item = u8>) -> Result<u16, DataError> {
    let mut num = [0; 2];
    for i in 0..2 {
        num[i] = data_iter.next().ok_or(DataError::InsufficientBytes)?;
    }
    Ok(u16::from_le_bytes(num))
}

fn read_u32(data_iter: &mut impl Iterator<Item = u8>) -> Result<u32, DataError> {
    let mut num = [0; 4];
    for i in 0..4 {
        num[i] = data_iter.next().ok_or(DataError::InsufficientBytes)?;
    }
    Ok(u32::from_le_bytes(num))
}

fn read_u64(data_iter: &mut impl Iterator<Item = u8>) -> Result<u64, DataError> {
    let mut num = [0; 8];
    for i in 0..8 {
        num[i] = data_iter.next().ok_or(DataError::InsufficientBytes)?;
    }
    Ok(u64::from_le_bytes(num))
}

/// current file version: 0
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

impl Entry {
    pub fn from_data(data: &[u8]) -> Result<Self, DataError> {
        let mut data_iter = data.iter().copied();
        Self::from_data_iter(&mut data_iter)
    }

    pub fn from_data_iter(data_iter: &mut impl Iterator<Item = u8>) -> Result<Self, DataError> {
        let (header_data, entry_type) = HeaderData::from_data_iter(data_iter)?;
        let entry_data = EntryData::from_data_iter(data_iter, entry_type)?;
        Ok(Entry {
            header_data,
            entry_data,
        })
    }

    pub fn into_data(&self) -> Vec<u8> {
        let mut data = Vec::new();
        self.extend_data(&mut data);
        data
    }

    pub fn extend_data(&self, data: &mut Vec<u8>) {
        self.header_data.extend_data(self.entry_data.get_discriminant(), data);
        self.entry_data.extend_data(data);
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

        let version = data_iter.next().ok_or(DataError::InsufficientBytes)?;
        if version != 0 {return Err(DataError::UnsupportedVersion)}

        let entry_type = data_iter.next().ok_or(DataError::InsufficientBytes)?;

        let parent_id = read_u64(data_iter)?;
        let num_children = read_u16(data_iter)?;
        let mut children_ids = Vec::new();
        for _ in 0..num_children {
            children_ids.push(read_u64(data_iter)?);
        }

        let author_id = read_u64(data_iter)?;
        Ok((HeaderData { version, parent_id, children_ids, author_id }, entry_type))
    }

    pub fn into_data(&self, entry_type: u8) -> Vec<u8> {
        let mut data = Vec::new();
        self.extend_data(entry_type, &mut data);
        data
    }

    pub fn extend_data(&self, entry_type: u8, data: &mut Vec<u8>) {
        data.extend_from_slice(&ENTRY_MAGIC_NUMBER.to_le_bytes());
        data.push(ENTRY_FILE_VERSION);
        data.push(entry_type);
        data.extend_from_slice(&self.parent_id.to_le_bytes());
        assert!(self.children_ids.len() <= u16::MAX as usize, "Failed to write entry: Too many children {}", self.children_ids.len());
        data.extend_from_slice(&(self.children_ids.len() as u16).to_le_bytes());
        data.extend(self.children_ids.iter().flat_map(|x| x.to_le_bytes()));
        data.extend_from_slice(&self.author_id.to_le_bytes());
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

    pub fn from_data_iter(data_iter: &mut impl Iterator<Item = u8>) -> Result<Self, DataError> {
        fn read_vec(data_iter: &mut impl Iterator<Item = u8>) -> Result<Vec<u64>, DataError> {
            let len = read_u32(data_iter)? as usize;
            let mut vec = Vec::with_capacity(len);
            for _ in 0..len {
                vec.push(read_u64(data_iter)?);
            }
            Ok(vec)
        }

        Ok(match DefaultBase::from_discriminant(data_iter.next().ok_or(DataError::InsufficientBytes)?)? {
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

    pub fn extend_data(&self, data: &mut Vec<u8>) {
        fn write_vec(vec: &[u64], data: &mut Vec<u8>) {
            assert!(vec.len() as u128 <= u32::MAX as u128, "Failed to write entry: too many ids in a DefaultedIdSet: {}", vec.len());
            data.extend_from_slice(&(vec.len() as u32).to_le_bytes());
            data.extend(vec.iter().flat_map(|x| x.to_le_bytes()));
        }

        data.push(self.get_default_base().get_discriminant());
        match self {
            Self::Inherit { whitelist_ids, blacklist_ids } => {
                write_vec(&whitelist_ids, data);
                write_vec(&blacklist_ids, data);
            }
            Self::White { blacklist_ids } => {
                write_vec(&blacklist_ids, data);
            }
            Self::Black { whitelist_ids } => {
                write_vec(&whitelist_ids, data);
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

    pub fn from_data(data: &[u8], entry_type: u8) -> Result<Self, DataError> {
        Self::from_data_iter(&mut data.iter().copied(), entry_type)
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

    pub fn into_data(&self) -> Vec<u8> {
        let mut data = Vec::new();
        self.extend_data(&mut data);
        data
    }

    pub fn extend_data(&self, data: &mut Vec<u8>) {
        match self {
            Self::Message { timestamp, message } => {
                data.extend_from_slice(&timestamp.to_le_bytes());
                assert!(message.len() <= u32::MAX as usize, "Failed to write entry: Message is too long: {}", message.len());
                data.extend_from_slice(&(message.len() as u32).to_le_bytes());
                data.extend_from_slice(message.as_bytes());
            }
            Self::AccessGroup { name, write_perms, read_perms } => {
                assert!(name.len() <= u32::MAX as usize, "Failed to write entry: Name is too long: {}", name.len());
                data.extend_from_slice(&(name.len() as u32).to_le_bytes());
                data.extend_from_slice(name.as_bytes());
                write_perms.extend_data(data);
                read_perms.extend_data(data);
            }
        }
    }
}

#[derive(Clone, Copy)]
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
    pub entry_ids: Vec<u64>,
}

impl UserData {
    pub fn new_empty() -> Self {
        UserData { entry_ids: Vec::new() }
    }

    pub fn from_data(data: &[u8]) -> Result<Self, DataError> {
        Self::from_data_iter(&mut data.iter().copied())
    }

    /// currrent file version 0
    /// 
    /// data format, numbers are little endian:
    ///     magic number (u16): see `USER_MAGIC_NUMBER`
    ///     version number (u8)
    ///     number of entry ids (u32),
    ///     entry id 1 (u64),
    ///     ...
    ///     entry id n (u64)
    pub fn from_data_iter(data_iter: &mut impl Iterator<Item = u8>) -> Result<Self, DataError> {
        let magic_number = read_u16(data_iter)?;
        if magic_number != USER_MAGIC_NUMBER {return Err(DataError::IncorrectMagicNum)};
        let version = data_iter.next().ok_or(DataError::InsufficientBytes)?;
        if version != 0 {return Err(DataError::UnsupportedVersion)};
        let num_entries = read_u32(data_iter)? as usize;
        let mut entry_ids = Vec::with_capacity(num_entries);
        for _ in 0..num_entries {
            entry_ids.push(read_u64(data_iter)?);
        }
        Ok(UserData { 
            entry_ids
        })
    }

    pub fn into_data(&self) -> Vec<u8> {
        let mut data = Vec::new();
        self.extend_data(&mut data);
        data
    }

    pub fn extend_data(&self, data: &mut Vec<u8>) {
        data.extend_from_slice(&USER_MAGIC_NUMBER.to_le_bytes());
        data.push(USER_FILE_VERSION);
        assert!(self.entry_ids.len() <= u32::MAX as usize, "Failed to write user: Too many entries: {}", self.entry_ids.len());
        data.extend_from_slice(&(self.entry_ids.len() as u32).to_le_bytes());
        data.extend(self.entry_ids.iter().flat_map(|x| x.to_le_bytes()));
    }
}

/// data format:
///     version (u8): 00
///     variant discriminant (u8) (listed with each variant)
///     - variant specific data -
/// 
/// GetEntry, 00:
///     user_id (u64)
///     entry_id (u64)
/// 
/// AddEntry, 01:
///     user_id (u64)
///     - Entry data - 
/// 
/// GetUser, 20:
///     user_id (u64)
/// 
/// AddUser, 21:
///     - no data -
#[derive(PartialEq, Eq, Debug)]
pub enum BoardRequest {
    GetEntry { user_id: u64, entry_id: u64 },
    AddEntry { user_id: u64, entry: Entry },
    GetUser { user_id: u64 },
    AddUser,
}

impl BoardRequest {
    pub fn from_data(data: &[u8]) -> Result<Self, DataError> {
        let data_iter = &mut data.iter().copied();
        let version = data_iter.next().ok_or(DataError::InsufficientBytes)?;
        if version != 0x00 {return Err(DataError::UnsupportedVersion)};
        let discriminant = data_iter.next().ok_or(DataError::InsufficientBytes)?;
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
            // user requests
            GET_USER => { // GetUser
                let user_id = read_u64(data_iter)?;
                BoardRequest::GetUser { user_id }
            }
            ADD_USER => { // AddUser
                BoardRequest::AddUser
            }
            
            _ => {return Err(DataError::InvalidDiscriminant)}
        })
    }

    pub fn into_data(&self) -> Vec<u8> {
        let mut data = Vec::new();
        self.extend_data(&mut data);
        data
    }

    pub fn extend_data(&self, data: &mut Vec<u8>) {
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
                entry.extend_data(data);
            },
            BoardRequest::GetUser { user_id } => {
                data.push(GET_USER);
                data.extend_from_slice(&user_id.to_le_bytes());
            },
            BoardRequest::AddUser => {
                data.push(ADD_USER);
            },
        };
    }
}

// the response 


#[derive(PartialEq, Eq, Debug)]
pub enum BoardResponse {
    GetEntry(Entry),
    AddEntry(u64),
    GetUser(UserData),
    AddUser(u64),
}

pub type MaybeBoardResponse = Result<BoardResponse, DataError>;

/// data format:
///     version (u8): 0
///     variant discriminant (u8) (listed with each variant)
/// 
/// GetEntry, 00:
///     - Entry Data -
/// 
/// AddEntry, 01:
///     entry_id (u64)
/// 
/// GetUser, 20:
///     - User Data -
/// 
/// AddUser, 21:
///     user_id (u64)
impl BoardResponse {
    pub fn from_data(data: &[u8]) -> Result<Self, DataError> {
        let mut data_iter = data.iter().copied();
        let version = data_iter.next().ok_or(DataError::InsufficientBytes)?;
        if version != 0 {return Err(DataError::UnsupportedVersion)}
        Ok(match data_iter.next().ok_or(DataError::InsufficientBytes)? {
            // entry requests
            GET_ENTRY => { // GetEntry
                let entry = Entry::from_data_iter(&mut data_iter)?;
                BoardResponse::GetEntry(entry)
            }
            ADD_ENTRY => { // AddEntry
                let entry_id = read_u64(&mut data_iter)?;
                BoardResponse::AddEntry(entry_id)
            }
            // user requests
            GET_USER => { // GetUser
                let user = UserData::from_data_iter(&mut data_iter)?;
                BoardResponse::GetUser(user)
            }
            ADD_USER => { // AddUser
                let user_id = read_u64(&mut data_iter)?;
                BoardResponse::AddUser(user_id)
            }
            ERROR => {
                
                return Err(DataError::InternalError);
            }
            _ => {return Err(DataError::InvalidDiscriminant)}
        })

    }

    pub fn into_data(val: &MaybeBoardResponse) -> Vec<u8> {
        let mut out = Vec::new();
        Self::extend_data(val, &mut out);
        out
    }

    pub fn extend_data(val: &MaybeBoardResponse, data: &mut Vec<u8>) {
        data.push(RESPONSE_FORMAT_VERSION);
        match val {
            Ok(BoardResponse::GetEntry(entry)) => {
                data.push(GET_ENTRY);
                entry.extend_data(data);
            }
            Ok(BoardResponse::AddEntry(entry_id)) => {
                data.push(ADD_ENTRY);
                data.extend_from_slice(&entry_id.to_le_bytes());
            }
            Ok(BoardResponse::GetUser(user)) => {
                data.push(GET_USER);
                user.extend_data(data);
            }
            Ok(BoardResponse::AddUser(user_id)) => {
                data.push(ADD_USER);
                data.extend_from_slice(&user_id.to_le_bytes());
            }
            Err(e) => { // TODO: should consider the error
                eprintln!("Sending Error: {:?}", e);
                data.push(ERROR);
            }
        }
    }
}