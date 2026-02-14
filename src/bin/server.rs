use message_board::*;
use std::collections::{HashMap, HashSet};
use std::io::{BufReader, Read, Write};
use std::net::*;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::sync::{Arc, RwLock};

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
///         user_id 1 (u64),
///         ...
///         user_id n (u64)
/// 
///     `users`, dir containing a file for each user:
///         each file is named after a user_id in hex,
///         see `lib.rs` for the user file format
///         
/// 

struct MessageBoard {
    file_dir: Box<Path>,
}

#[allow(unused)]
impl MessageBoard {
    /// encapsulation method to get the raw, unparsed data of an entry in the form of an iter
    /// use is generally prefered over `get_entry_data`
    /// 
    /// may or may not be implemented in terms of `get_entry_data`
    fn get_entry_data_iter(&self, entry_id: u64) -> Result<impl Iterator<Item = u8>, DataError> {
        let mut path = PathBuf::from(self.file_dir.clone());
        path.push(format!("entries/{:08X}", entry_id));
        let entry = std::fs::File::open(path).map_err(|_| DataError::DoesNotExist)?;
        Ok(BufReader::new(entry).bytes().filter_map(|x| x.ok())) // Scuff
    }

    /// encapsulation method to get a `UserData` of a `user_id`
    fn get_user(&self, user_id: u64) -> Result<UserData, DataError> {
        let mut path = PathBuf::from(self.file_dir.clone());
        path.push(format!("users/{:08X}", user_id));
        UserData::from_data(&std::fs::read(path).map_err(|_| DataError::DoesNotExist)?)
    }

    /// encapsulation method to write an `Entry` at `entry_id`
    /// 
    /// requires that the entry_id doesn't currently exist
    fn write_entry(&self, entry_id: u64, entry: Entry) -> Result<(), DataError> {
        let mut path = PathBuf::from(self.file_dir.clone());
        path.push(format!("entries/{:08X}", entry_id));
        let exists = fs::exists(&path).map_err(|_| DataError::InternalError)?;
        if exists {return Err(DataError::AlreadyExists);}
        fs::write(path, entry.into_data()).map_err(|_| DataError::InternalError)?;
        Ok(())
    }

    /// encapsulation method to force write an `Entry` at `entry_id`
    /// 
    /// can be used to edit entries unlike `write_entry` but is otherwise identical
    fn force_write_entry(&self, entry_id: u64, entry: Entry) -> Result<(), DataError> {
        let mut path = PathBuf::from(self.file_dir.clone());
        path.push(format!("entries/{:08X}", entry_id));
        fs::write(path, entry.into_data()).map_err(|_| DataError::InternalError)?;
        Ok(())
    }

    /// encapsulation method to write an updated `UserData` for `user_id`
    /// 
    /// requires that the user_id currently exists
    fn write_user_data(&self, user_id: u64, data: UserData) -> Result<(), DataError> {
        let mut path = PathBuf::from(self.file_dir.clone());
        path.push(format!("users/{:08X}", user_id));
        let exists = fs::exists(&path).map_err(|_| DataError::InternalError)?;
        if !exists {return Err(DataError::DoesNotExist);}

        fs::write(path, data.into_data()).map_err(|x| DataError::InternalError)?;
        Ok(())
    }


    fn get_user_list(&self) -> Result<Vec<u64>, DataError> {
        let mut path = PathBuf::from(self.file_dir.clone());
        path.push("user_list");
        let data = fs::read(path).map_err(|x| DataError::DoesNotExist)?;
        let (data, remainder) = data.as_chunks::<8>();
        if remainder.len() != 0 {return Err(DataError::InsufficientBytes)} // FIXME: questionable error
        Ok(data.iter().map(|x| u64::from_le_bytes(*x)).collect::<Vec<_>>())
    }

    fn get_entry(&self, entry_id: u64) -> Result<Entry, DataError> {
        Entry::from_data_iter(&mut self.get_entry_data_iter(entry_id)?)
    }

    fn add_entry(&self, user_id:u64, entry_id: u64, entry: Entry) -> Result<(), DataError> {
        self.write_entry(entry_id, entry)?;
        let mut user_data = self.get_user(user_id)?;
        user_data.entry_ids.push(entry_id);
        self.write_user_data(user_id, user_data)?;
        Ok(())
    }

    /// checks if the user has perms to the *children* of the entry
    fn has_access_perm(&self, user_id: u64, entry_id: u64) -> Result<bool, DataError> {
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
                } = EntryData::from_data_iter(&mut data_iter, entry_type)? else {panic!("EntryData read as an AccessGroup should match an AccessGroup")};

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

    fn add_user(&self, new_user_id: u64) -> Result<(), DataError> {
        let mut path = PathBuf::from(self.file_dir.clone());
        path.push("user_list");
        let mut user_list = std::fs::File::open(&path).map_err(|_| DataError::InternalError)?;
        user_list.write_all(&new_user_id.to_le_bytes()).map_err(|_| DataError::InternalError)?; // FIXME?: check if this could actually be meaningfully communicated
        path.clear();
        path.push(&self.file_dir);
        path.push(format!("users/{:08X}", new_user_id));
        fs::File::create(&path).map_err(|_| DataError::AlreadyExists)?;
        Ok(())
    }

    /// spawns a command handler thread which handles requests generated by the server and clients_read
    fn command_handler(&'static self, response_tx: mpsc::Sender<BoardResponse>, handler_id: u64) -> mpsc::Sender<BoardRequest> {
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            fn handle_request(board: &MessageBoard, request: BoardRequest) -> Result<BoardResponseData, DataError> {
                match request {
                    BoardRequest::GetEntry { user_id, entry_id} => {
                        let entry = board.get_entry(entry_id)?;
                        if entry.header_data.author_id != user_id && !board.has_access_perm(user_id, entry.header_data.parent_id)? {
                            return Err(DataError::InsufficientPerms.into())
                        }
                        Ok(BoardResponseData::GetEntry(entry))
                    }
                    BoardRequest::AddEntry { user_id , entry_id , entry} => {
                        if !board.has_access_perm(user_id, entry.header_data.parent_id)? {
                            return Err(DataError::InsufficientPerms.into())
                        }
                        board.add_entry(user_id, entry_id, entry)?;
                        Ok(BoardResponseData::AddEntry)
                    }
                    BoardRequest::GetUser { user_id } => {
                        let user = board.get_user(user_id)?;
                        Ok(BoardResponseData::GetUser(user))
                    }
                    BoardRequest::AddUser { user_id } => {
                        let users = board.get_user_list()?;
                        if users.contains(&user_id) {return Err(DataError::AlreadyExists.into())}
                        board.add_user(user_id)?;
                        Ok(BoardResponseData::AddUser)
                    }
                }
            }

            for request in rx {
                let response = BoardResponse {
                    handler_id,
                    data: handle_request(&self, request),
                };
                let _ = response_tx.send(response);
            }
        });
        tx
    }
}

struct Server {
    board: MessageBoard,
    client_id_map: Arc<RwLock<HashMap<u64, TcpStream>>>,
    next_client_id: std::cell::Cell<u64>,
}

impl Server {
    fn new(board: MessageBoard) -> Self {
        Server { 
            board, 
            client_id_map: Arc::new(RwLock::new(HashMap::new())),
            next_client_id: std::cell::Cell::new(0),
        }
    }

    fn mainloop(&'static  self) {
        let (incomind_queue_tx, incoming_queue_rx) = mpsc::channel();
        let (outgoing_queue_tx, outgoing_queue_rx) = mpsc::channel();

        let Server { board, client_id_map, next_client_id: _} = self;
        //let client_id_map: &_ = client_id_map;

        // incoming
        std::thread::spawn(move || {
            let mut clients_read = Vec::new();
            let mut read_id_set = HashSet::new();
            let mut to_remove = Vec::new();
            loop {
                std::hint::spin_loop();
                for idx in 0..clients_read.len() {
                    let (id,  client): &mut (u64, TcpStream) = &mut clients_read[idx];

                    let mut request_size = [0u8; 8];
                    let Ok(bytes_read) = client.peek(&mut request_size) else {client_id_map.write().unwrap().remove(id); continue;}; // just assuming disconnect
                    if bytes_read < 8 {continue;} // should send some error
                    let request_size = u64::from_le_bytes(request_size) as usize;
                    let mut request = vec![0u8; request_size + 8];
                    if client.read_exact(&mut request).is_err() {continue}; // should send some error
                    let Ok(request) = BoardRequest::from_data(&request) else {continue}; // should send some error
                    incomind_queue_tx.send((*id, request)).expect("Queue Rx should be alive");
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
                    let BoardResponse{handler_id, data} = response_rx.recv().expect("command_handler threads should keep response_tx alive");
                    let client_id = handler_clients[handler_id as usize].take().expect("Handlers should only respond for a registered client");
                    outgoing_queue_tx.send((client_id, data)).expect("The Outgoing Receiver should never drop");
                    num_active -= 1;
                } else if num_active < num_threads {
                    std::hint::spin_loop();
                    if let Ok((client_id, request)) = incoming_queue_rx.try_recv() {
                        let mut sent_to_handler = false;
                        for (client, handler) in handler_clients.iter_mut().zip(&mut handler_threads) {
                            if client.is_some() {continue;}
                            
                            *client = Some(client_id);
                            handler.send(request).expect("The Command Handler should never drop");
                            sent_to_handler = true;
                            num_active += 1;
                            break;
                        }
                        if !sent_to_handler {
                            eprintln!("dropped a request (no available handler)");
                            num_active = num_threads; //evidently, they are all active
                        }
                    }
                    if let Ok(BoardResponse{handler_id, data}) = response_rx.try_recv() {
                        let client_id = handler_clients[handler_id as usize].take().expect("Handlers should only respond for a registered client");
                        outgoing_queue_tx.send((client_id, data)).expect("The Outgoing Receiver should never drop");
                        num_active -= 1;
                    }
                } else if num_active > num_threads {
                    eprintln!("More active handlers than threads for handlers, attempting recovery");
                    num_active = 4;
                } else {
                    eprintln!("Less than 0 active handlers, attempting recovery");
                    num_active = 0;
                }
            }
        });
        //outgoing
        std::thread::spawn(move || {
            let mut clients_write: HashMap<u64, TcpStream> = HashMap::new();
            let mut unresolved_messages = Vec::new();

            loop {
                std::hint::spin_loop();
                for (id, message) in outgoing_queue_rx.try_iter() {
                    let Some(client) = clients_write.get_mut(&id) else {unresolved_messages.push((id, message)); continue;};
                    let _ = client.write_all(&BoardResponseData::into_data(message)); // should push to unresolved_messages
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
                    for (id, message) in unresolved_messages.drain(..) {
                        let Some(client) = clients_write.get_mut(&id) else {eprintln!("client for id not found, dropping unresolved message"); continue;};
                        let _ = client.write_all(&BoardResponseData::into_data(message)); // should push to unresolved_messages
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

    let board = MessageBoard { file_dir };
    
    println!("MessageBoard successfully established");

    let server = Box::leak(Box::new( Server::new(board)));
    server.mainloop();

    let listener = TcpListener::bind(String::from("127.0.0.1:") + &PORT.to_string()).unwrap();
    for stream in listener.incoming() {
        if let Ok(stream) = stream {
            println!("Connection recieved");
            server.add_client(stream);
        } else {
            println!("Connection error");
        }
    }
}