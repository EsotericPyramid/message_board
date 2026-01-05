use std::path::Path;

pub const PORT: u16 = 8000;
pub const ROOT_ID: u64 = 0x00_00_00_00;
pub const ENTRY_MAGIC_NUMBER: u16 = 0x1234;
pub const USER_MAGIC_NUMBER: u16 = 0x1470;

/// file versions
pub const ENTRY_FILE_VERSION: u8 = 0x00;
pub const USRE_FILE_VERSION: u8 = 0x00;

/// file discriminants
pub const MESSAGE: u8 = 0x00;
pub const ACCESS_GROUP: u8 = 0x01;

/// access group
pub const INHERIT_BASE: u8 = 0x00;
pub const WHITE_BASE: u8 = 0x01;
pub const BLACK_BASE: u8 = 0x02;

#[cfg(test)]
pub mod tests;

fn read_u16(data_iter: &mut impl Iterator<Item = u8>) -> Option<u16> {
    let mut num = [0; 2];
    for i in 0..2 {
        num[i] = data_iter.next()?;
    }
    Some(u16::from_le_bytes(num))
}

fn read_u32(data_iter: &mut impl Iterator<Item = u8>) -> Option<u32> {
    let mut num = [0; 4];
    for i in 0..4 {
        num[i] = data_iter.next()?;
    }
    Some(u32::from_le_bytes(num))
}

fn read_u64(data_iter: &mut impl Iterator<Item = u8>) -> Option<u64> {
    let mut num = [0; 8];
    for i in 0..8 {
        num[i] = data_iter.next()?;
    }
    Some(u64::from_le_bytes(num))
}

pub struct Entry {
    pub entry_data: EntryData,
    pub header_data: HeaderData,
}

pub enum EntryError {
    DuplicateID,
    FileIOError(std::io::Error),
    Utf8Error(std::string::FromUtf8Error),
    HeaderError,
    MessageError,
    AccessGroupError,
    NoReaderForVersion,
    InsufficientPerms,
}

impl Entry {
    pub fn from_path(path: &Path) -> Result<Self, EntryError> {
        let file_result = std::fs::read(path);
        let Ok(file_data) = file_result else {return Err(EntryError::FileIOError(file_result.err().expect("Expecting an Err from a let else")))};

        Self::from_data(&file_data)
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
    ///     overrides / doesn't preserve perms (bool, 1 byte),
    ///     number of whitelist ids (u32),
    ///     whitelist id 1 (u64),
    ///     ...
    ///     whitelist id n (u64),
    ///     number of blacklist ids (u32),
    ///     blacklist id 1 (u64),
    ///     ...
    ///     blacklist id n (u64),
    /// 
    /// 
    pub fn from_data(data: &[u8]) -> Result<Self, EntryError> {
        let mut data_iter = data.iter().copied();

        let (header_data, entry_type) = HeaderData::from_data_iter(&mut data_iter)?;
        let entry_data = EntryData::from_data_iter(&mut data_iter, entry_type)?;
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

pub struct HeaderData {
    pub version: u8,
    pub parent_id: u64,
    pub children_ids: Vec<u64>,
    pub author_id: u64,
}

impl HeaderData {
    pub fn from_path(path: &Path) -> Result<(Self, u8), EntryError> {
        let file_result = std::fs::read(path);
        let Ok(file_data) = file_result else {return Err(EntryError::FileIOError(file_result.err().expect("Expecting an Err from a let else")))};

        Self::from_data(&file_data)
    }

    /// gives a HeaderData and the entry type
    pub fn from_data(data: &[u8]) -> Result<(Self, u8), EntryError> {
        let mut data_iter = data.iter().copied();
        HeaderData::from_data_iter(&mut data_iter)
    }

    /// gives a HeaderData and the entry type
    pub fn from_data_iter(data_iter: &mut impl Iterator<Item = u8>) -> Result<(Self, u8), EntryError> {
        let magic_number = read_u16(data_iter).ok_or(EntryError::HeaderError)?;
        if magic_number != ENTRY_MAGIC_NUMBER {return Err(EntryError::HeaderError)}

        let version = data_iter.next().ok_or(EntryError::HeaderError)?;
        if version != 0 {return Err(EntryError::NoReaderForVersion)}

        let entry_type = data_iter.next().ok_or(EntryError::HeaderError)?;

        let parent_id = read_u64(data_iter).ok_or(EntryError::HeaderError)?;
        let num_children = read_u16(data_iter).ok_or(EntryError::HeaderError)?;
        let mut children_ids = Vec::new();
        for _ in 0..num_children {
            children_ids.push(read_u64(data_iter).ok_or(EntryError::HeaderError)?);
        }

        let author_id = read_u64(data_iter).ok_or(EntryError::HeaderError)?;
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
    }
}

pub enum EntryData {
    Message {
        timestamp: u64,
        message: String,
    },
    AccessGroup {
        name: String,
        access_base: AccessBase,
        whitelist_ids: Vec<u64>,
        blacklist_ids: Vec<u64>,
    },
}

impl EntryData {
    pub fn get_discriminant(&self) -> u8 {
        match self {
            Self::Message { timestamp: _, message: _ } => MESSAGE,
            Self::AccessGroup { name: _, access_base: _, whitelist_ids: _, blacklist_ids: _ } => ACCESS_GROUP
        }
    }

    pub fn from_data(data: &[u8], entry_type: u8) -> Result<Self, EntryError> {
        Self::from_data_iter(&mut data.iter().copied(), entry_type)
    }

    pub fn from_data_iter(data_iter: &mut impl Iterator<Item = u8>, entry_type: u8) -> Result<Self, EntryError> {
        Ok(match entry_type {
            MESSAGE => { // Message
                let timestamp = read_u64(data_iter).ok_or(EntryError::MessageError)?;
                let message_size = read_u32(data_iter).ok_or(EntryError::MessageError)? as usize;
                let message = String::from_utf8(data_iter.take(message_size).collect::<Vec<_>>()).map_err(|e| EntryError::Utf8Error(e))?;
                EntryData::Message { timestamp, message }
            }
            ACCESS_GROUP => { // AccessGroup
                let name_len = read_u32(data_iter).ok_or(EntryError::AccessGroupError)? as usize;
                let name = String::from_utf8((data_iter).take(name_len).collect::<Vec<_>>()).map_err(|e| EntryError::Utf8Error(e))?;
                let access_base_discriminant = data_iter.next().ok_or(EntryError::AccessGroupError)?;
                let access_base;
                if access_base_discriminant == INHERIT_BASE {
                    access_base = AccessBase::Inherit;
                } else if access_base_discriminant == BLACK_BASE {
                    access_base = AccessBase::Black;
                } else if access_base_discriminant == WHITE_BASE {
                    access_base = AccessBase::White;
                } else {
                    return Err(EntryError::AccessGroupError)
                }

                let num_whitelist_ids = read_u32(data_iter).ok_or(EntryError::AccessGroupError)?;
                let mut whitelist_ids = Vec::with_capacity(num_whitelist_ids as usize);
                for _ in 0..num_whitelist_ids {
                    whitelist_ids.push(read_u64(data_iter).ok_or(EntryError::AccessGroupError)?);
                }
                let num_blacklist_ids = read_u32(data_iter).ok_or(EntryError::AccessGroupError)?;
                let mut blacklist_ids = Vec::with_capacity(num_blacklist_ids as usize);
                for _ in 0..num_blacklist_ids {
                    blacklist_ids.push(read_u64(data_iter).ok_or(EntryError::AccessGroupError)?);
                }
                EntryData::AccessGroup { name, access_base, whitelist_ids, blacklist_ids }
            }
            _ => {return Err(EntryError::HeaderError)}
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
            Self::AccessGroup { name, access_base, whitelist_ids, blacklist_ids } => {
                assert!(name.len() <= u32::MAX as usize, "Failed to write entry: Name is too long: {}", name.len());
                data.extend_from_slice(&(name.len() as u32).to_le_bytes());
                data.extend_from_slice(name.as_bytes());
                data.push(access_base.get_discriminant());
                assert!(whitelist_ids.len() <= u32::MAX as usize, "Failed to write entry: too many whitelist ids: {}", whitelist_ids.len());
                data.extend_from_slice(&(whitelist_ids.len() as u32).to_le_bytes());
                data.extend(whitelist_ids.iter().flat_map(|x| x.to_le_bytes()));
                assert!(blacklist_ids.len() <= u32::MAX as usize, "Failed to write entry: too many blacklist ids: {}", blacklist_ids.len());
                data.extend_from_slice(&(blacklist_ids.len() as u32).to_le_bytes());
                data.extend(blacklist_ids.iter().flat_map(|x| x.to_le_bytes()));
            }
        }
    }
}

pub enum AccessBase {
    Inherit,
    White,
    Black,
}

impl AccessBase {
    pub fn get_discriminant(&self) -> u8 {
        match self {
            Self::Inherit => INHERIT_BASE,
            Self::White => WHITE_BASE,
            Self::Black => BLACK_BASE,
        }
    }
}

pub struct UserData {
    pub entry_ids: Vec<u64>,
}

pub enum UserError {
    FileIOError(std::io::Error),
    Utf8Error,
    FormattingError,
    DoesNotExist,
    DuplicateID,
}

impl UserData {
    pub fn from_data(data: &[u8]) -> Result<Self, UserError> {
        Self::from_data_iter(&mut data.iter().copied())
    }

    /// currrent file version 0
    /// 
    /// data format, numbers are little endian:
    ///     magic number (u16): see `USER_MAGIC_NUMBER`
    ///     number of entry ids (u32),
    ///     entry id 1 (u64),
    ///     ...
    ///     entry id n (u64)
    pub fn from_data_iter(data_iter: &mut impl Iterator<Item = u8>) -> Result<Self, UserError> {
        let magic_number = read_u16(data_iter).ok_or(UserError::FormattingError)?;
        if magic_number != USER_MAGIC_NUMBER {return Err(UserError::FormattingError)};
        let num_entries = read_u32(data_iter).ok_or(UserError::FormattingError)? as usize;
        let mut entry_ids = Vec::with_capacity(num_entries);
        for _ in 0..num_entries {
            entry_ids.push(read_u64(data_iter).ok_or(UserError::FormattingError)?);
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
        assert!(self.entry_ids.len() > u32::MAX as usize, "Failed to write user: Too many entries: {}", self.entry_ids.len());
        data.extend_from_slice(&(self.entry_ids.len() as u32).to_le_bytes());
        data.extend(self.entry_ids.iter().flat_map(|x| x.to_le_bytes()));
    }
}

pub enum DataError {
    Entry(EntryError),
    User(UserError)
}

impl From<EntryError> for DataError {
    fn from(value: EntryError) -> Self {
        DataError::Entry(value)
    }
}

impl From<UserError> for DataError {
    fn from(value: UserError) -> Self {
        DataError::User(value)
    }
}

pub enum BoardRequest {
    GetEntry { user_id: u64, entry_id: u64 },
    AddEntry { user_id: u64, entry_id: u64, entry: Entry },
    GetUser { user_id: u64 },
    AddUser { user_id: u64 },
}

// the response 
pub struct BoardResponse {
    pub handler_id: u64,
    pub data: Result<BoardResponseData, DataError>,
}

pub enum BoardResponseData {
    GetEntry(Entry),
    AddEntry,
    GetUser(UserData),
    AddUser
}

impl BoardResponseData {
    pub fn into_data(&self) -> Vec<u8> {
        todo!()
    }
}