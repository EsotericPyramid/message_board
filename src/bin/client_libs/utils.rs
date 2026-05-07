use crossterm::event::Event;
use message_board::cryptography::{get_crypto_rng, CryptoRng};
use message_board::*;
use ratatui::layout::{Constraint, Layout};
use ratatui::widgets::{Clear};
use std::io::{Read, Write};
use std::net::*;
use ratatui::{
    text::{Line, Text},
    widgets::{Block, Paragraph, Widget},
    layout::Rect,
    buffer::Buffer,
};
use message_board::internal_error;
use super::super::*;


pub fn read_long_hex_string(string: &str) -> Result<Vec<u8>, DataError> {
    let mut iter = string.chars();
    let mut data = Vec::with_capacity(iter.size_hint().0 / 2);
    loop {
        let Some(char1) = iter.next() else {break;};
        let Some(char2) = iter.next() else {return Err(DataError::InsufficientBytes)};
        let mut byte_string = String::with_capacity(2);
        byte_string.push(char1);
        byte_string.push(char2);
        data.push(u8::from_str_radix(&byte_string, 16).map_err(|_| DataError::NotHex)?);
    }
    Ok(data)
}

pub fn write_long_hex_string(hex: &[u8]) -> String {
    let mut out = String::with_capacity(hex.len() * 2);
    for byte in hex {
        out.push_str(&format!("{:02X}", byte));
    }
    out
}

#[macro_export]
macro_rules! left {
    () => {KeyCode::Char('h') | KeyCode::Left};
}
#[macro_export]
macro_rules! down {
    () => {KeyCode::Char('j') | KeyCode::Down};
}
#[macro_export]
macro_rules! up {
    () => {KeyCode::Char('k') | KeyCode::Up};
}
#[macro_export]
macro_rules! right {
    () => {KeyCode::Char('l') | KeyCode::Right};
}

#[macro_export]
macro_rules! pass_direction {
    ($expr:expr) => {
        match $expr {
            left!() => {return Some(StateChange::MoveLeft)}
            down!() => {return Some(StateChange::MoveDown)}
            up!() => {return Some(StateChange::MoveUp)}
            right!() => {return Some(StateChange::MoveRight)}
            x => {x}
        } 
    };
}


#[derive(Debug)]
pub enum StateChange {
    // Movements, if reasonable, move to the widget in the indicated dir (changing state as appropriate), if not, do nothing
    MoveRight, 
    MoveLeft,
    MoveDown,
    MoveUp,
    // Global state changes, only larger things should need this
    Push(ClientState),
    Pop,
    Swap(ClientState),
    // The meaning of this is entirely dependent on the specific widget
    Blank // means it was handled but no state change
}

pub trait InputWidget {
    fn render(&self, area: Rect, buf: &mut Buffer) -> Rect;

    fn handle_event(&mut self, event: Event) -> Option<StateChange>;
    // these functions may not mean anything for some widgets
    fn reload(&mut self) -> Result<(), DataError> {Ok(())}

    fn focus(&mut self) {}
    fn unfocus(&mut self) {}

    fn consume_child(&mut self, child: ClientState) -> Option<StateChange>;
}


#[derive(Debug)]
pub struct MessageBoardConnection {
    stream: TcpStream,
    user_id: Option<UserId>,
    keys: PublicKeySet,
    crypto_rng: CryptoRng,
}

impl MessageBoardConnection {
    pub fn new(config: &Config) -> Self {
        let mut connected_stream = None;
        while connected_stream.is_none() {
            let stream = TcpStream::connect((&config.server_address as &str, PORT));
            if let Ok(stream) = stream {
                connected_stream = Some(stream);
            } else if let Err(e) = stream {
                eprintln!("Connection failed: {}", e);
            }
        }
        
        let mut board = Self { 
            stream: connected_stream.unwrap(), 
            user_id: config.user_id, 
            keys: PublicKeySet::new(None, config.user_aead.as_ref().map(|x| x.clone())),
            crypto_rng: get_crypto_rng(),
        };
        if let Some(user_id) = board.user_id {
            if let Err(e) = board.get_user(user_id) {
                eprintln!("User Id not found on server ({:?})", e);
                eprintln!("If this is correct, set it to \"None\"");
            }
        } else {
            let _ = board.create_user(); // FIXME: should notify in some way if a new one was minted
        }
        board.update_kem().unwrap();
        board
    }

    fn send_request(&mut self, request: BoardRequest) -> Result<BoardResponse, DataError> {
        let request = request.secure_into_data(&mut self.crypto_rng, &mut self.keys)?;
        let _ = self.stream.write_all(&(request.len() as u64).to_le_bytes());
        let _ = self.stream.write_all(&request);
        let mut num_bytes = [0; 8];
        let _ = self.stream.read_exact(&mut num_bytes);
        let num_bytes = u64::from_le_bytes(num_bytes) as usize;
        let mut buffer = vec![0; num_bytes];
        let _ = self.stream.read_exact(&mut buffer);
        BoardResponse::secure_from_data(&buffer, &mut self.keys)
    }

    pub fn get_entry(&mut self, entry_id: EntryId) -> Result<Entry, DataError> {
        let request = BoardRequest::GetEntry { user_id: self.user_id.unwrap(), entry_id };
        let response = self.send_request(request)?;
        let BoardResponse::GetEntry(entry) = response else {return Err(internal_error!())};
        Ok(entry)
    }

    pub fn write_entry(&mut self, entry: Entry) -> Result<EntryId, DataError> {
        let request = BoardRequest::AddEntry { user_id: self.user_id.unwrap(), entry };
        let response = self.send_request(request)?;
        let BoardResponse::AddEntry(entry_id) = response else {return Err(internal_error!())};
        Ok(entry_id)
    }

    pub fn edit_entry(&mut self, entry_id: EntryId, entry: Entry) -> Result<(), DataError> {
        let request = BoardRequest::EditEntry { user_id: self.user_id.unwrap(), entry_id, entry };
        let response = self.send_request(request)?;
        let BoardResponse::EditEntry = response else {return Err(internal_error!())};
        Ok(())
    }

    pub fn get_user(&mut self, user_id: UserId) -> Result<UserData, DataError> {
        let request = BoardRequest::GetUser { user_id };
        let response = self.send_request(request)?;
        let BoardResponse::GetUser(user) = response else {return Err(internal_error!())};
        Ok(user)
    }

    pub fn create_user(&mut self) -> Result<bool, DataError> {
        //if let Some(_) = self.user_id {return Ok(false)}
        let request = BoardRequest::AddUser;
        let response = self.send_request(request)?;
        let BoardResponse::AddUser{user_id, user_aead} = response else {return Err(internal_error!())};
        self.user_id = Some(user_id);
        self.keys.user_aead = Some(user_aead.clone());
        edit_config(|config| {config.user_id = Some(user_id); config.user_aead = Some(user_aead)});
        Ok(true)
    }

    pub fn update_kem(&mut self) -> Result<(), DataError> {
        let request = BoardRequest::GetKemEk;
        let response = self.send_request(request)?;
        let BoardResponse::GetKemEk(kem_ek) = response else {return Err(internal_error!())};
        self.keys.kem = Some(kem_ek);
        Ok(())
    }

    pub fn get_user_id(&self) -> &Option<UserId> {&self.user_id}
}

impl Drop for MessageBoardConnection {
    fn drop(&mut self) {
        edit_config(|config| {
            config.user_aead = self.keys.user_aead.clone();
        });
    }
}

#[derive(Debug)]
pub struct Terminal {
    term: Option<ratatui::DefaultTerminal>,
}

impl Terminal {
    pub fn new() -> Self {
        Self {
            term: Some(ratatui::init())
        }
    }

    pub fn pause<F: FnOnce() -> O, O>(&mut self, f: F) -> O {
        if self.term.is_none() {eprintln!("Terminal invariant broken: accessible while self.term = None")};
        ratatui::restore();
        self.term = None;
        let out = f();
        self.term = Some(ratatui::init());
        out
    }
}

impl std::ops::Deref for Terminal {
    type Target = ratatui::DefaultTerminal;

    fn deref(&self) -> &Self::Target {
        self.term.as_ref().expect("Terminal invariant broken: accessible while self.term = None")
    }
}

impl std::ops::DerefMut for Terminal {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.term.as_mut().expect("Terminal invariant broken: accessible while self.term = None")
    }
}


impl Drop for Terminal {
    fn drop(&mut self) {
        if self.term.is_some() {ratatui::restore();}
    }
}

#[derive(Debug)]
pub enum ClientState {
    Viewer(EntryTreeViewer),
    WriteVarientSelection(EntryVariantSelector),
    TextEntry(TextEntry),
    AccessGroupBuilder(AccessGroupBuilder),
    AccessGroupIdList(AccessGroupIdList),
    Error(Vec<DataError>),
}

impl InputWidget for ClientState {
    fn reload(&mut self) -> Result<(), DataError> {
        match self {
            ClientState::Viewer(viewer) => viewer.reload(),
            ClientState::WriteVarientSelection(selector) => selector.reload(),
            ClientState::TextEntry(entry) => entry.reload(),
            ClientState::AccessGroupBuilder(builder) => builder.reload(),
            ClientState::AccessGroupIdList(id_list) => id_list.reload(),
            ClientState::Error(..) => Ok(()),
        }
    }

    fn render(&self, area: Rect, buf: &mut Buffer) -> Rect {
        match self {
            ClientState::Viewer(viewer) => viewer.render(area, buf),
            ClientState::WriteVarientSelection(selector) => selector.render(area, buf),
            ClientState::TextEntry(entry) => entry.render(area, buf),
            ClientState::AccessGroupBuilder(builder) => builder.render(area, buf),
            ClientState::AccessGroupIdList(id_list) => id_list.render(area, buf),
            ClientState::Error(errors) => {
                let mut layout = Layout::horizontal([Constraint::Fill(1), Constraint::Percentage(50), Constraint::Fill(1)]).split(area);
                layout = Layout::vertical([Constraint::Fill(1), Constraint::Percentage(50), Constraint::Fill(1)]).split(layout[1]);
                let error_popup_area = layout[1];

                let block = Block::bordered().title(" Error(s) ");

                let mut text = Text::default();
                for error in errors {
                    let line = Line::from(format!("{:?}", error));
                    text.push_line(line);
                }

                Clear.render(error_popup_area, buf);
                Paragraph::new(text).block(block).render(error_popup_area, buf);
                error_popup_area
            }
        }
    }

    fn handle_event(&mut self, event: Event) -> Option<StateChange> {
        match self {
            ClientState::Viewer(viewer) => viewer.handle_event(event),
            ClientState::WriteVarientSelection(selector) => selector.handle_event(event),
            ClientState::TextEntry(entry) => entry.handle_event(event),
            ClientState::AccessGroupBuilder(builder) => builder.handle_event(event),
            ClientState::AccessGroupIdList(id_list) => id_list.handle_event(event),
            ClientState::Error(_) => {Some(StateChange::Pop)},
        }
    }

    fn focus(&mut self) {
        match self {
            ClientState::Viewer(viewer) => viewer.focus(),
            ClientState::WriteVarientSelection(selector) => selector.focus(),
            ClientState::TextEntry(entry) => entry.focus(),
            ClientState::AccessGroupBuilder(builder) => builder.focus(),
            ClientState::AccessGroupIdList(id_list) => id_list.focus(),
            ClientState::Error(_) => {},
        }
    }
    fn unfocus(&mut self) {
        match self {
            ClientState::Viewer(viewer) => viewer.unfocus(),
            ClientState::WriteVarientSelection(selector) => selector.unfocus(),
            ClientState::TextEntry(entry) => entry.unfocus(),
            ClientState::AccessGroupBuilder(builder) => builder.unfocus(),
            ClientState::AccessGroupIdList(id_list) => id_list.unfocus(),
            ClientState::Error(_) => {},
        }
    }

    fn consume_child(&mut self, child: ClientState) -> Option<StateChange> {
        match self {
            ClientState::Viewer(viewer) => viewer.consume_child(child),
            ClientState::WriteVarientSelection(selector) => selector.consume_child(child),
            ClientState::TextEntry(entry) => entry.consume_child(child),
            ClientState::AccessGroupBuilder(builder) => builder.consume_child(child),
            ClientState::AccessGroupIdList(id_list) => id_list.consume_child(child),
            ClientState::Error(_) => {Some(StateChange::Pop)},
        }
    }
}

impl ToString for ClientState {
    fn to_string(&self) -> String {
        String::from(match self {
            ClientState::Viewer(..) => "Viewer",
            ClientState::WriteVarientSelection(..) => "WriteVarientSelection",
            ClientState::AccessGroupBuilder(..) => "AccessGroupBuilder",
            ClientState::AccessGroupIdList(..) => "AccessGroupIdList",
            ClientState::TextEntry(..) => "TextEntry",
            ClientState::Error(..) => "Error",
        })
    }
}