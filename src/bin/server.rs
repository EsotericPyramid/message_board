use log::*;
use message_board::cryptography::{get_crypto_rng, get_kem_set, DecapsulationKey, EncapsulationKey, UserAeadKey};
use message_board::*;
use std::borrow::Borrow;
use std::hash::Hash;
use std::collections::{HashMap, HashSet};
use std::io::{BufReader, Read, Write};
use std::net::*;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::sync::RwLock;
use std::time::{Instant, Duration};
use rand::Rng;
use message_board::utils::*;
// this is the 0.6.4 version, vs the 0.10.0 version from the rand crate
use rand_chacha::rand_core::RngCore as OldRngCore;
use rand_chacha::rand_core::CryptoRng as OldCryptoRng; 

/// extended off of the user home
const RC_FILE: &str = ".config/message_board/server_rc.toml";

const ROOT_ENTRY_ID: u64 = 0;


const SERVER_MAINLOOP_PERIOD: Duration = Duration::new(0, 1000000); // ie. 1 ms

struct StorageFile {
    kem_ek: EncapsulationKey,
    kem_dk: DecapsulationKey,
}

struct GuardedUserAeadKey<'a> {
    board: &'a MessageBoard,
    user_id: UserId,
    key: UserAeadKey,
}

impl<'a> std::ops::Deref for GuardedUserAeadKey<'a> {
    type Target = UserAeadKey;

    fn deref(&self) -> &Self::Target {&self.key}
}

impl<'a> std::ops::DerefMut for GuardedUserAeadKey<'a> {
    fn deref_mut(&mut self) -> &mut Self::Target {&mut self.key}
}

impl<'a> Drop for GuardedUserAeadKey<'a> {
    fn drop(&mut self) {
        let mut user = self.board.get_user(self.user_id).unwrap();
        user.aead = self.key.clone();
        self.board.overwrite_user_data(self.user_id, user).unwrap();
    }
}

/// file format:
/// 
/// all numbers are little endian
/// 
/// `~/.config/message_board` is the config dir:
///     path: file containing the path for the main file dir (hereafter `file_dir`)
/// 
/// `file_dir`:
///     `storage`, file containing some persistent information for the server:
///         kem_ek: EncapsulationKey,
///         kem_dk: DecapsulationKey,
/// 
///     `entries`, dir containing entry files:
///         each entry file has no extension and is named with its id in hex
///         see `lib.rs` for the entry file format
/// 
///         special entry files:
///             0:  the root entry, this entry *MUST* exist,
///                                 access group which is its own parent but not its own child,
///           
/// 
///     `users`, dir containing a file for each user:
///         each file is named after a user_id in hex,
///         see `lib.rs` for the user file format
/// 
///         special user ids:
///             0:  the server itself, this id should never be associated with a human action
///             1:  generic admin, this id should only be usable on the server itself and isn't beholden to standard permisions
///             2:  anonymous, TBD
///         
///         
/// 
struct MessageBoard {
    address: String,
    file_dir: Box<Path>,
    entry_ids: RwLock<HashSet<u64>>,
    user_ids: RwLock<HashSet<UserId>>,
}

#[allow(unused)]
impl MessageBoard {
    fn new() -> Self {
        let user_home = std::env::home_dir().unwrap();
        let mut real_rc_config = user_home.clone();
        real_rc_config.push(RC_FILE);
        
        let mut stdin = std::io::stdin();
        let mut stdout = std::io::stdout();
        let mut input_buffer = String::new();
        let mut rc_config_result = fs::read_to_string(&real_rc_config).map(|str| str.parse::<toml::Table>().expect("The Server Rc was misformatted"));
        if let Err(e) = rc_config_result {
            match e.kind() {
                std::io::ErrorKind::NotFound => {
                    print!("Config file does not exist, create a new one? (y/n): ");
                    let _ = stdout.flush();
                    input_buffer.clear();
                    let create = stdin_y_n(&mut stdin, &mut input_buffer);
                    if create {
                        let mut contents = toml::Table::new();
                        print!("Please enter the path for the message board's data: ");
                        let _ = stdout.flush();
                        input_buffer.clear();
                        let _ = stdin.read_line(&mut input_buffer);
                        contents.insert("path".to_string(), toml::Value::String(input_buffer.trim().to_string()));

                        print!("Please enter the IP address / host name for the message board: ");
                        let _ = stdout.flush();
                        input_buffer.clear();
                        let _ = stdin.read_line(&mut input_buffer);
                        contents.insert("address".to_string(), toml::Value::String(input_buffer.trim().to_string()));

                        let mut parent = real_rc_config.clone();
                        parent.pop();
                        if let Err(e) = fs::create_dir_all(parent) {panic!("Failed to create the ~/.config/message_board directory: {}", e)};
                        if let Err(e) = fs::write(&real_rc_config, &contents.to_string()) {panic!("Failed to write the config file: {}", e)};
                        rc_config_result = Ok(contents);
                    } else {
                        panic!("Cannot continue without a config file, terminating the server");
                    }
                }
                _ => panic!("terminating due to non-specifc config file read error: {}", e.kind())
            }
        }
        let rc_config = rc_config_result.unwrap();
        let file_dir = PathBuf::from(rc_config["path"].as_str().expect("\"path\" should be a string of the path to where files should be stored")).into_boxed_path();
        let address = rc_config["address"].as_str().expect("\"path\" should be a string of the path to where files should be stored").to_string();
    
        let board = MessageBoard { 
            address,
            file_dir,
            entry_ids: RwLock::new(HashSet::new()),
            user_ids: RwLock::new(HashSet::new()),
        };
        
        debug!("MessageBoard config successfully established");
        // checking / setting up the board files

        let mut missing_files = false;
        {
            let mut path = PathBuf::from(board.file_dir.clone());
            missing_files |= !path.exists();
            path.push("entries");
            missing_files |= !path.exists();
            path.push(format!("{:016X}", ROOT_ENTRY_ID));
            missing_files |= !path.exists();
            path.pop();
            path.pop();
            path.push("users");
            missing_files |= !path.exists();
            path.pop();
            path.push("storage");
            missing_files |= !path.exists();
        }
        if missing_files {
            print!("MessageBoard is missing files at path. Create empty files as needed? (y/n): ");
            let _ = stdout.flush();
            input_buffer.clear();
            let create = stdin_y_n(&mut stdin, &mut input_buffer);
            if create {
                let mut crypto_rng = get_crypto_rng();

                let _ = fs::create_dir_all(&board.file_dir);
                let mut path = PathBuf::from(board.file_dir.clone());
                path.push("entries");
                let _ = fs::create_dir(&path);
                path.pop();
                path.push("users");
                let _ = fs::create_dir(&path);
                path.pop();
                path.push("storage");
                let _ = fs::write(path, &[]);

                let (kem_dk, kem_ek) = get_kem_set(crypto_rng);
                let storage = StorageFile {
                    kem_dk,
                    kem_ek
                };
                board.write_storage_file(storage);

                let default_root = Entry {
                    header_data: HeaderData { version: ENTRY_FILE_VERSION, parent_id: ROOT_ENTRY_ID, children_ids: Vec::new(), author_id: SERVER_USER_ID.into() },
                    entry_data: EntryData::AccessGroup { name: String::from("Root"), write_perms: DefaultedIdSet::White { blacklist_ids: Vec::new() }, read_perms: DefaultedIdSet::White { blacklist_ids: Vec::new() }}
                };
                if board.write_entry(ROOT_ENTRY_ID, default_root).is_err_and(|e| if let DataError::AlreadyExists = e {false} else {true}) {
                    error!("failed to create root entry");
                }
            } else {
                panic!("Cannot continue without board files, terminating the server");
            }
        }

        board.update_user_ids();
        board.update_entry_ids();
        board
    }

    fn write_new<P: AsRef<Path>>(path: P, contents: &[u8]) -> Result<(), DataError> {
        fs::File::create_new(path).map_err(|_| DataError::AlreadyExists)?.write_all(contents).map_err(|_| internal_error!())?;
        Ok(())
    }

    fn overwrite_old<P: AsRef<Path>>(path: P, contents: &[u8]) -> Result<(), DataError> {
        fs::File::options().write(true).truncate(true).open(&path).map_err(|_| DataError::DoesNotExist)?.write_all(contents).map_err(|_| internal_error!())?;
        Ok(())
    }

    fn append_old<P: AsRef<Path>>(path: P, contents: &[u8]) -> Result<(), DataError> {
        fs::File::options().write(true).append(true).open(&path).map_err(|_| DataError::DoesNotExist)?.write_all(contents).map_err(|_| internal_error!())?;
        Ok(())
    }

    fn generate_unique_id<ID: Eq + Hash + Borrow<u64> + From<u64>>(mut rng: impl Rng, used_ids: &HashSet<ID>) -> ID {
        let mut rand_num = rng.next_u64();
        while used_ids.contains(&rand_num) {
            rand_num += 1;
        }
        rand_num.into()
    }

    /// encapsulation method to get the raw, unparsed data of an entry in the form of an iter
    /// use is generally prefered over `get_entry_data`
    /// 
    /// may or may not be implemented in terms of `get_entry_data`
    fn get_entry_data_iter(&self, entry_id: u64) -> Result<impl Iterator<Item = u8>, DataError> {
        let mut path = PathBuf::from(self.file_dir.clone());
        path.push(format!("entries/{:016X}", entry_id));
        let entry = std::fs::File::open(path).map_err(|_| DataError::DoesNotExist)?;
        Ok(BufReader::new(entry).bytes().filter_map(|x| x.ok())) // Scuff
    }

    /// encapsulation method to get a `UserData` of a `user_id`
    fn get_user(&self, user_id: UserId) -> Result<UserData, DataError> {
        let mut path = PathBuf::from(self.file_dir.clone());
        path.push(format!("users/{}", user_id));
        UserData::from_data(&std::fs::read(path).map_err(|_| DataError::DoesNotExist)?)
    }

    /// encapsulation method to write an `Entry` at `entry_id`
    /// 
    /// requires that the entry_id doesn't currently exist
    fn write_entry(&self, entry_id: u64, entry: Entry) -> Result<(), DataError> {
        let mut path = PathBuf::from(self.file_dir.clone());
        path.push(format!("entries/{:016X}", entry_id));
        Self::write_new(path, &entry.into_data()?)
    }

    /// encapsulation method to overwrite / edit an `Entry` at `entry_id`
    /// 
    /// requires that the entry_id currently exists
    fn overwrite_entry(&self, entry_id: u64, new_entry: Entry) -> Result<(), DataError> {
        let mut path = PathBuf::from(self.file_dir.clone());
        path.push(format!("entries/{:016X}", entry_id));
        Self::overwrite_old(path, &new_entry.into_data()?)
    }

    /// encapsulation method to overwrite an updated `UserData` for `user_id`
    /// 
    /// requires that the user_id currently exists
    fn overwrite_user_data(&self, user_id: UserId, new_data: UserData) -> Result<(), DataError> {
        let mut path = PathBuf::from(self.file_dir.clone());
        path.push(format!("users/{}", user_id));
        Self::overwrite_old(path, &new_data.into_data()?) //FIXME: completely overwrites, even for small edits
    }

    fn read_storage_file(&self) -> StorageFile {
        let mut path = PathBuf::from(self.file_dir.clone());
        path.push("storage");
        let mut data = std::fs::read(path).unwrap().into_iter();
        let kem_ek = EncapsulationKey::from_data_iter(&mut data).unwrap();
        let kem_dk = DecapsulationKey::from_data_iter(&mut data).unwrap();
        StorageFile { kem_ek, kem_dk }
    }

    fn write_storage_file(&self, storage_file: StorageFile) {
        let mut path = PathBuf::from(self.file_dir.clone());
        path.push("storage");
        let mut data = Vec::new();
        storage_file.kem_ek.extend_data(&mut data).unwrap();
        storage_file.kem_dk.extend_data(&mut data).unwrap();
        Self::overwrite_old(path, &data);
    }

    fn get_user_aead(&self, user_id: UserId) -> Result<GuardedUserAeadKey<'_>, DataError> {
        let user = self.get_user(user_id)?;
        Ok(GuardedUserAeadKey {
            board: self,
            user_id,
            key: user.aead,
        })
    }

    fn update_user_ids(&self) -> Result<(), DataError> {
        let mut path = PathBuf::from(self.file_dir.clone());
        path.push("users");
        let new = fs::read_dir(&path).map_err(|_| internal_error!())?.map(|user_file| {
            u64::from_str_radix(user_file.unwrap().file_name().to_str().unwrap(), 16).unwrap().into()
        }).collect();
        {
            *self.user_ids.write().unwrap() = new;
        }
        Ok(())
    }

    fn update_entry_ids(&self) -> Result<(), DataError> {
        let mut path = PathBuf::from(self.file_dir.clone());
        path.push("entries");
        *self.entry_ids.write().unwrap() = fs::read_dir(&path).map_err(|_| internal_error!())?.map(|entry_file| {
            u64::from_str_radix(entry_file.unwrap().file_name().to_str().unwrap(), 16).unwrap()
        }).collect();
        Ok(())
    }

    fn get_entry(&self, entry_id: u64) -> Result<Entry, DataError> {
        Entry::from_data_iter(&mut self.get_entry_data_iter(entry_id)?)
    }

    fn add_entry(&self, user_id: UserId, entry_id: u64, entry: Entry) -> Result<(), DataError> {
        let mut parent = self.get_entry(entry.header_data.parent_id)?;
        parent.header_data.children_ids.push(entry_id);
        self.overwrite_entry(entry.header_data.parent_id, parent)?;
        
        let mut user_data = self.get_user(user_id)?;
        user_data.entry_ids.push(entry_id);
        self.overwrite_user_data(user_id, user_data)?;

        self.write_entry(entry_id, entry)?;
        Ok(())
    }

    fn edit_entry(&self, user_id: UserId, entry_id: u64, entry: Entry) -> Result<(), DataError> {
        self.overwrite_entry(entry_id, entry)
    }

    /// checks if the user has read_perms to the *children* of the entry
    fn has_read_perm(&self, user_id: UserId, entry_id: u64) -> Result<bool, DataError> {
        let mut data_iter = self.get_entry_data_iter(entry_id)?;
        let (mut header, mut entry_type) = HeaderData::from_data_iter(&mut data_iter)?;
        let mut current_id = entry_id;
        loop {
            if entry_type == ACCESS_GROUP {
                let EntryData::AccessGroup {
                    name: _,
                    write_perms: _,
                    read_perms,
                } = EntryData::from_data_iter(&mut data_iter, entry_type)? else {panic!("EntryData read as an AccessGroup should match an AccessGroup")};

                if let Some(has_perm) = read_perms.contains(user_id) {
                    return Ok(has_perm);
                }
            }
            if current_id == ROOT_ID {
                break;
            }
            current_id = header.parent_id;
            data_iter = self.get_entry_data_iter(header.parent_id)?;
            (header, entry_type) = HeaderData::from_data_iter(&mut data_iter)?;
        } 
        // FIXME: should be a specialized Err
        Ok(false)
    }

    /// checks if the user has perms to the *children* of the entry
    fn has_write_perm(&self, user_id: UserId, entry_id: u64) -> Result<bool, DataError> {
        let mut data_iter = self.get_entry_data_iter(entry_id)?;
        let (mut header, mut entry_type) = HeaderData::from_data_iter(&mut data_iter)?;
        let mut current_id = entry_id;
        loop {
            if entry_type == ACCESS_GROUP {
                let EntryData::AccessGroup {
                    name: _,
                    write_perms,
                    read_perms: _,
                } = EntryData::from_data_iter(&mut data_iter, entry_type)? else {panic!("EntryData read as an AccessGroup should match an AccessGroup")};

                if let Some(has_perm) = write_perms.contains(user_id) {
                    return Ok(has_perm);
                }
            }
            if current_id == ROOT_ID {
                break;
            }
            current_id = header.parent_id;
            data_iter = self.get_entry_data_iter(header.parent_id)?;
            (header, entry_type) = HeaderData::from_data_iter(&mut data_iter)?;
        } 
        // FIXME: should be a specialized Err
        Ok(false)
    }

    fn add_user(&self, crypto_rng: impl OldCryptoRng + OldRngCore, new_user_id: UserId) -> Result<UserData, DataError> {
        let key = UserAeadKey::new_random(crypto_rng);
        let mut path = PathBuf::from(self.file_dir.clone());
        path.push(format!("users/{}", new_user_id));
        let data = UserData::new_empty(key);
        Self::write_new(&path, &data.into_data()?);
        Ok(data)
    }

    /// spawns a command handler thread which handles requests generated by the server and clients_read
    fn command_handler(&'static self, response_tx: mpsc::Sender<(u64, BoardResponse)>, handler_id: u64) -> mpsc::Sender<BoardRequest> {
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            fn handle_request(board: &MessageBoard, rng: impl Rng, mut crypto_rng: impl OldCryptoRng + OldRngCore, request: BoardRequest) -> MaybeBoardResponse {
                match request {
                    BoardRequest::GetEntry { user_id, entry_id} => {
                        info!("Request Type: GetEntry");
                        let entry = board.get_entry(entry_id)?;
                        if entry.header_data.author_id != user_id && !board.has_read_perm(user_id, entry.header_data.parent_id)? {
                            return Err(DataError::InsufficientPerms.into())
                        }
                        Ok(BoardResponse::GetEntry(entry))
                    }
                    BoardRequest::AddEntry { user_id , entry} => {
                        info!("Request Type: AddEntry");
                        if !board.has_write_perm(user_id, entry.header_data.parent_id)? {
                            return Err(DataError::InsufficientPerms.into())
                        }
                        let entry_id = MessageBoard::generate_unique_id(rng, &board.entry_ids.read().unwrap());
                        board.add_entry(user_id, entry_id, entry)?;
                        Ok(BoardResponse::AddEntry(entry_id))
                    }
                    BoardRequest::EditEntry { user_id, entry_id, entry } => {
                        info!("Request Type: EditEntry");
                        let old_entry = board.get_entry(entry_id)?;
                        if entry.header_data.author_id != user_id || old_entry.header_data.author_id != user_id {
                            return Err(DataError::InsufficientPerms)
                        }
                        if (entry.header_data.children_ids != old_entry.header_data.children_ids) | (entry.header_data.parent_id != old_entry.header_data.parent_id) {
                            return Err(DataError::EdittedLocation)
                        }
                        board.edit_entry(user_id, entry_id, entry)?;
                        Ok(BoardResponse::EditEntry)
                    }
                    BoardRequest::GetUser { user_id } => {
                        info!("Request Type: GetUser");
                        let user = board.get_user(user_id)?;
                        Ok(BoardResponse::GetUser(user))
                    }
                    BoardRequest::AddUser => {
                        info!("Request Type: AddUser");
                        let user_id = MessageBoard::generate_unique_id(rng, &board.user_ids.read().unwrap()).into();
                        let user = board.add_user(&mut crypto_rng, user_id)?;
                        Ok(BoardResponse::AddUser{user_id, user_aead: user.aead})
                    }
                    BoardRequest::GetKemEk => {//should be handled by server
                        return Err(internal_error!()); 
                    }
                }
            }

            let mut rng = rand::rng();
            let mut crypto_rng = get_crypto_rng();
            for request in rx {
                let response = (
                    handler_id,
                    BoardResponse::encapsulate_error(handle_request(&self, &mut rng, &mut crypto_rng, request)),
                );
                let _ = response_tx.send(response);
            }
        });
        tx
    }
}

struct Server {
    board: MessageBoard,
    client_id_map: RwLock<HashMap<u64, TcpStream>>,
    next_client_id: std::cell::Cell<u64>,
    kem_ek: EncapsulationKey,
    kem_dk: DecapsulationKey,
}

impl Server {
    fn new(board: MessageBoard) -> Self {
        let storage = board.read_storage_file();
        Server { 
            board, 
            client_id_map: RwLock::new(HashMap::new()),
            next_client_id: std::cell::Cell::new(0),
            kem_ek: storage.kem_ek,
            kem_dk: storage.kem_dk,
        }
    }

    fn mainloop(&'static  self) {
        let (incomind_queue_tx, incoming_queue_rx) = mpsc::channel();
        let (outgoing_queue_tx, outgoing_queue_rx) = mpsc::channel();
        let decode_error_queue_tx = outgoing_queue_tx.clone();

        let Server { board, client_id_map, kem_dk, kem_ek, ..} = self;
        //let client_id_map: &_ = client_id_map;

        // incoming
        std::thread::spawn(move || {
            let mut clients_read = Vec::new();
            let mut read_id_set = HashSet::new();
            let mut to_remove = Vec::new();
            let timer = Instant::now();
            let mut iter_start_time = Duration::new(0, 0);
            loop {
                let ideal_iter_start_time = iter_start_time + SERVER_MAINLOOP_PERIOD;
                let elapsed = timer.elapsed();
                if ideal_iter_start_time > elapsed {std::thread::sleep(ideal_iter_start_time - elapsed)}
                iter_start_time = timer.elapsed();

                for idx in 0..clients_read.len() {
                    let (id,  client): &mut (u64, TcpStream) = &mut clients_read[idx];

                    let mut request_size = [0u8; 8];
                    let Ok(bytes_read) = client.peek(&mut request_size) else {client_id_map.write().unwrap().remove(id); continue;}; // just assuming disconnect
                    if bytes_read < 8 {continue;}
                    let request_size = u64::from_le_bytes(request_size) as usize;
                    let mut request = vec![0u8; request_size + 8];
                    if client.read_exact(&mut request).is_err() {continue}; // should send some error
                    info!("Received {} byte message", request_size);
                    match BoardRequest::secure_from_data(kem_dk, |user_id| {
                        board.get_user_aead(user_id).map_err(|e| {info!("Failed to retrieve User Aead for {}: {:?}", user_id, e); e}).ok()
                    },&request[8..]) {
                        Ok((re_encyption_data, request)) => {
                            incomind_queue_tx.send((*id, re_encyption_data, request)).expect("Queue Rx should be alive");
                        }
                        Err(e) => {
                            info!("Failed to Parse Request: {:?}", e); 
                            decode_error_queue_tx.send((*id, ReEncryptionData::Exposed, BoardResponse::Error(e))).expect("Queue Rx should be alive");
                        }
                    }
                }

                if let Ok(mut global_id_map) = client_id_map.try_write() {
                    for id in to_remove.drain(..) {
                        global_id_map.remove(&id);
                    }
                }

                if let Ok(global_id_map) = client_id_map.try_read() {               
                    // note: to_remove may not have been emptied 
                    // removing dropped clients
                    clients_read = clients_read.into_iter().filter(|x| global_id_map.contains_key(&x.0) & !to_remove.contains(&x.0)).collect();
                    // adding new clients
                    for (id, client) in global_id_map.iter() {
                        if !read_id_set.contains(id)  {
                            // if this fails, it will be reattempted next iter
                            if let Ok(client) = client.try_clone() {
                                clients_read.push((*id, client));
                                read_id_set.insert(*id);
                            }
                        }
                    }
                }
            }
        });
        // distribution to and from handlers 
        std::thread::spawn(move || {
            let (response_tx, response_rx) = mpsc::channel();
            let num_threads = 4;
            let mut handler_threads = Vec::new();
            let timer = Instant::now();
            let mut iter_start_time = Duration::new(0, 0);

            for handler_id in 0..num_threads {
                handler_threads.push(board.command_handler(response_tx.clone(), handler_id));
            }
            let mut handler_clients = Vec::new();
            for _ in 0..num_threads {
                handler_clients.push(None);
            }
            let mut num_active = 0;
            
            loop {
                if num_active == num_threads {
                    // note: blocking
                    let (handler_id, data) = response_rx.recv().expect("command_handler threads should keep response_tx alive");
                    let (client_id, re_encryption_data) = handler_clients[handler_id as usize].take().expect("Handlers should only respond for a registered client");
                    outgoing_queue_tx.send((client_id, re_encryption_data, data)).expect("The Outgoing Receiver should never drop");
                    num_active -= 1;
                } else if num_active < num_threads {
                    let ideal_iter_start_time = iter_start_time + SERVER_MAINLOOP_PERIOD;
                    let elapsed = timer.elapsed();
                    if ideal_iter_start_time > elapsed {std::thread::sleep(ideal_iter_start_time - elapsed)}
                    iter_start_time = timer.elapsed();

                    if let Ok((client_id, re_encryption_data, request)) = incoming_queue_rx.try_recv() {
                        if let BoardRequest::GetKemEk = request {
                            info!("Request Type: GetKemEk");
                            outgoing_queue_tx.send((client_id, re_encryption_data, BoardResponse::GetKemEk(kem_ek.clone()))).expect("The Outgoing Receiver should never drop");
                        } else {
                            let mut sent_to_handler = false;
                            for (client, handler) in handler_clients.iter_mut().zip(&mut handler_threads) {
                                if client.is_some() {continue;}
                                
                                *client = Some((client_id, re_encryption_data));
                                handler.send(request).expect("The Command Handler should never drop");
                                sent_to_handler = true;
                                num_active += 1;
                                break;
                            }
                            if !sent_to_handler {
                                error!("dropped a request (no available handler)");
                                num_active = num_threads; //evidently, they are all active
                            }
                        }
                    }
                    if let Ok((handler_id, data)) = response_rx.try_recv() {
                        let (client_id, re_encryption_data) = handler_clients[handler_id as usize].take().expect("Handlers should only respond for a registered client");
                        outgoing_queue_tx.send((client_id, re_encryption_data, data)).expect("The Outgoing Receiver should never drop");
                        num_active -= 1;
                    }
                } else if num_active > num_threads {
                    warn!("More active handlers than threads for handlers, attempting recovery");
                    num_active = 4;
                } else {
                    warn!("Less than 0 active handlers, attempting recovery");
                    num_active = 0;
                }
            }
        });
        //outgoing
        std::thread::spawn(move || {
            fn send_reponse(board: &MessageBoard, crypto_rng: impl OldCryptoRng + OldRngCore, re_encryption_data: ReEncryptionData, message: BoardResponse, client: &mut TcpStream) {
                let message = message.secure_into_data(crypto_rng, re_encryption_data, |user_id| {
                    board.get_user_aead(user_id).ok()
                }).unwrap_or_else(|_| {
                    error!("Failed to encode server response"); BoardResponse::Error(internal_error!()).into_data().unwrap()
                });
                info!("Sending {} byte message", message.len());
                let _ = client.write_all(&(message.len() as u64).to_le_bytes());
                let _ = client.write_all(&message); 
            }

            let mut clients_write: HashMap<u64, TcpStream> = HashMap::new();
            let mut unresolved_messages = Vec::new();
            let timer = Instant::now();
            let mut iter_start_time = Duration::new(0, 0);

            let mut crypto_rng = get_crypto_rng();

            loop {
                let ideal_iter_start_time = iter_start_time + SERVER_MAINLOOP_PERIOD;
                let elapsed = timer.elapsed();
                if ideal_iter_start_time > elapsed {std::thread::sleep(ideal_iter_start_time - elapsed)}
                iter_start_time = timer.elapsed();

                for (id, re_encryption_data, message) in outgoing_queue_rx.try_iter() {
                    let Some(client) = clients_write.get_mut(&id) else {unresolved_messages.push((id, re_encryption_data, message)); continue;};
                    send_reponse(board, &mut crypto_rng, re_encryption_data, message, client);
                }

                if let Ok(global_id_map) = client_id_map.try_read() {               
                    // note: to_remove may not have been emptied 
                    // removing dropped clients
                    clients_write = clients_write.into_iter().filter(|x| global_id_map.contains_key(&x.0)).collect();
                    // adding new clients
                    for (id, client) in global_id_map.iter() {
                        if !clients_write.contains_key(id) {
                            if let Ok(client) = client.try_clone() {
                                clients_write.insert(*id, client);
                            }
                        }
                    }
                    drop(global_id_map); // getting rid of the guard
                    for (id, re_encryption_data, message) in unresolved_messages.drain(..) {
                        let Some(client) = clients_write.get_mut(&id) else {info!("client for id not found, dropping unresolved message"); continue;};
                        send_reponse(board, &mut crypto_rng, re_encryption_data, message, client);
                    }
                }
            }
        });
    }

    fn add_client(&self, client: TcpStream) {
        let mut client_id_map = self.client_id_map.write().expect("The RwLock shouldnt be poisoned");
        let mut next_client_id = self.next_client_id.get();
        while client_id_map.contains_key(&next_client_id) {next_client_id += 1;}
        client_id_map.insert(next_client_id, client);
        self.next_client_id.set(next_client_id +1);
    }
}

fn main() {
    env_logger::init();

    let board = MessageBoard::new();
    let listener = TcpListener::bind((&board.address as &str, PORT)).unwrap();

    let server = Box::leak(Box::new( Server::new(board)));
    server.mainloop();

    for stream in listener.incoming() {
        if let Ok(stream) = stream {
            info!("Connection recieved");
            server.add_client(stream);
        } else {
            warn!("Connection error");
        }
    }
}