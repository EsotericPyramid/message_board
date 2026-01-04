use message_board::*;
use std::io::{BufReader, Read, Write};
use std::net::*;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::mpsc;

/// extended off of the user home
const PATH_CONFIG: &str = ".config/message_board/path.txt";


/// file format:
/// 
/// all numbers are little endian
/// 
/// `~/.config/message_board` is the config dir:
///     path: file containing the path for the main file dir (hereafter `file_dir`)
/// 
/// `file_dir`:
///     `entries`, dir containing entry files:
///         each entry file has no extension and is named with its id in hex
///         see `lib.rs` for the entry file format
/// 
///         special entry files:
///             00000000:   the root entry, this entry *MUST* exist,
///                         access group which is its own parent but not its own child with a white access base, 
///           
///     `user_list`, a file of all the user ids:
///         magic_number (u16) (see, `USER_LIST_MAGIC_NUMBER`),
///         user_id 1 (u64),
///         ...
///         user_id n (u64)
/// 
///     `users`, dir containing a file for each user:
///         each file is named after a user_id in hex,
///         see `lib.rs` for the user file format
///         
/// 

struct Server {
    file_dir: Box<Path>,
    clients: Vec<Option<TcpStream>>,
}

impl Server {
    /// encapsulation method to get the raw, unparsed data of an entry
    /// 
    /// may or may not be implemented in terms of `get_entry_data_iter`
    fn get_entry_data(&self, entry_id: u64) -> Result<Vec<u8>, EntryError> {
        let mut path = PathBuf::from(self.file_dir.clone());
        path.push(format!("entries/{:08X}", entry_id));
        std::fs::read(path).map_err(|x| EntryError::FileIOError(x))
    }

    /// encapsulation method to get the raw, unparsed data of an entry in the form of an iter
    /// use is generally prefered over `get_entry_data`
    /// 
    /// may or may not be implemented in terms of `get_entry_data`
    fn get_entry_data_iter(&self, entry_id: u64) -> Result<impl Iterator<Item = u8>, EntryError> {
        let mut path = PathBuf::from(self.file_dir.clone());
        path.push(format!("entries/{:08X}", entry_id));
        let entry = std::fs::File::open(path).map_err(|x| EntryError::FileIOError(x))?;
        Ok(BufReader::new(entry).bytes().filter_map(|x| x.ok())) // Scuff
    }

    /// encapsulation method to get a `UserData` of a `user_id`
    fn get_user(&self, user_id: u64) -> Result<UserData, UserError> {
        let mut path = PathBuf::from(self.file_dir.clone());
        path.push(format!("users/{:08X}", user_id));
        UserData::from_data(&std::fs::read(path).map_err(|x| UserError::FileIOError(x))?)
    }

    /// encapsulation method to write an `Entry` at `entry_id`
    /// 
    /// requires that the entry_id doesn't currently exist
    fn write_entry(&self, entry_id: u64, entry: Entry) -> Result<(), EntryError> {
        let mut path = PathBuf::from(self.file_dir.clone());
        path.push(format!("entries/{:08X}", entry_id));
        let exists = fs::exists(&path).map_err(|x| EntryError::FileIOError(x))?;
        if exists {return Err(EntryError::DuplicateID);}
        fs::write(path, entry.into_data()).map_err(|x| EntryError::FileIOError(x))?;
        Ok(())
    }

    /// encapsulation method to force write an `Entry` at `entry_id`
    /// 
    /// can be used to edit entries unlike `write_entry` but is otherwise identical
    fn force_write_entry(&self, entry_id: u64, entry: Entry) -> Result<(), EntryError> {
        let mut path = PathBuf::from(self.file_dir.clone());
        path.push(format!("entries/{:08X}", entry_id));
        fs::write(path, entry.into_data()).map_err(|x| EntryError::FileIOError(x))?;
        Ok(())
    }

    /// encapsulation method to write an updated `UserData` for `user_id`
    /// 
    /// requires that the user_id currently exists
    fn write_user_data(&self, user_id: u64, data: UserData) -> Result<(), UserError> {
        let mut path = PathBuf::from(self.file_dir.clone());
        path.push(format!("users/{:08X}", user_id));
        let exists = fs::exists(&path).map_err(|x| UserError::FileIOError(x))?;
        if !exists {return Err(UserError::DoesNotExist);}

        fs::write(path, data.into_data()).map_err(|x| UserError::FileIOError(x))?;
        Ok(())
    }

    fn process_clients(&mut self) {
        todo!()
    }

    fn clean_clients(&mut self) {
        let mut old_clients = Vec::with_capacity(self.clients.len());
        std::mem::swap(&mut self.clients, &mut old_clients);
        self.clients.extend(old_clients.into_iter().filter(|x| x.is_some()));
    }

    fn get_entry(&self, entry_id: u64) -> Result<Entry, EntryError> {
        Entry::from_data(&self.get_entry_data(entry_id)?)
    }

    fn add_entry(&self, user_id:u64, entry_id: u64, entry: Entry) -> Result<(), DataError> {
        self.write_entry(entry_id, entry).map_err(|x| DataError::Entry(x))?;
        let mut user_data = self.get_user(user_id).map_err(|x| DataError::User(x))?;
        user_data.entry_ids.push(entry_id);
        self.write_user_data(user_id, user_data).map_err(|x| DataError::User(x))?;
        Ok(())
    }

    /// checks if the user has perms to the *children* of the entry
    fn has_access_perm(&self, user_id: u64, entry_id: u64) -> Result<bool, EntryError> {
        let mut data_iter = self.get_entry_data_iter(entry_id)?;
        let (mut header, mut entry_type) = HeaderData::from_data_iter(&mut data_iter)?;
        let mut current_id = entry_id;
        loop {
            if entry_type == ACCESS_GROUP {
                let EntryData::AccessGroup {
                    name: _,
                    access_base,
                    whitelist_ids,
                    blacklist_ids,
                } = EntryData::from_data_iter(&mut data_iter, entry_type)? else {return Err(EntryError::HeaderError)};

                if whitelist_ids.contains(&user_id) {
                    return Ok(true);
                } else if blacklist_ids.contains(&user_id) {
                    return Ok(false);
                }

                if let AccessBase::White = access_base {
                    return Ok(true);
                } else if let AccessBase::Black = access_base {
                    return Ok(false);
                }
            }
            if current_id == ROOT_ID {
                break;
            }
            current_id = header.parent_id;
            let mut data_iter = self.get_entry_data_iter(header.parent_id)?;
            (header, entry_type) = HeaderData::from_data_iter(&mut data_iter)?;
        } 
        // FIXME: should be a specialized Err
        Ok(false)
    }

    fn add_user(&self, new_user_id: u64) -> Result<(), UserError> {
        let mut path = PathBuf::from(self.file_dir.clone());
        path.push("user_list");
        let mut user_list = std::fs::File::open(&path).map_err(|e| UserError::FileIOError(e))?;
        user_list.write_all(&new_user_id.to_le_bytes()).map_err(|e| UserError::FileIOError(e))?;
        path.clear();
        path.push(format!("{}/users/{:08X}", self.file_dir.to_str().ok_or(UserError::Utf8Error)?, new_user_id));
        fs::File::create(&path).map_err(|x| UserError::FileIOError(x))?;
        Ok(())
    }
}



fn main() {
    let user_home = std::env::home_dir().unwrap();
    let mut real_path_config = user_home.clone();
    real_path_config.push(PATH_CONFIG);

    let file_dir;
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    let mut input_buffer = String::new();
    loop {
        let file_dir_result = fs::read_to_string(&real_path_config);
        if let Err(e) = file_dir_result {
            match e.kind() {
                std::io::ErrorKind::NotFound => {
                    print!("Config file does not exist, create a new one? (y/n): ");
                    let _ = stdout.flush();
                    input_buffer.clear();
                    let _ = stdin.read_line(&mut input_buffer);
                    input_buffer = input_buffer.trim().to_lowercase();
                    if input_buffer == "y" {
                        print!("Please enter the path for the message board's data: ");
                        let _ = stdout.flush();
                        loop {
                            input_buffer.clear();
                            let _ = stdin.read_line(&mut input_buffer);
                            let mut parent = real_path_config.clone();
                            parent.pop();
                            if let Err(e) = fs::create_dir_all(parent) {
                                println!("Write error: {}", e);
                                continue;
                            }
                            if let Err(e) = fs::write(&real_path_config, input_buffer.trim()) {
                                println!("Write error: {}", e);
                            }
                            
                        }
                    } else if input_buffer == "n" {
                        println!("Cannot continue without a config file, terminating the server");
                        return;
                    }
                }
                _ => {println!("terminating due to non-specifc config file read error: {}", e.kind()); return;}
            }
        } else {
            file_dir = PathBuf::from(file_dir_result.unwrap()).into_boxed_path();
            break;
        }
    }

    let mut server = Server { file_dir, clients: Vec::new() };
    
    println!("Server successfully established");

    let listener = TcpListener::bind(String::from("127.0.0.1:") + &PORT.to_string()).unwrap();
    for stream in listener.incoming() {
        if let Ok(stream) = stream {
            println!("Connection recieved");
            server.clients.push(Some(stream));
        } else {
            println!("Connection error");
        }
    }
}