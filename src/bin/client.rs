use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use message_board::*;
use ratatui::layout::{Constraint, Layout};
use ratatui::style::{Stylize};
use ratatui::widgets::Clear;
use std::io::{Read, Write};
use std::net::*;
use ratatui::{
    text::{Line, Text},
    widgets::{Block, Paragraph, Widget},
    layout::Rect,
    buffer::Buffer,
};
use message_board::utils::*;

const ENTRY_VARIANTS: [EntryVariant; 2] = [
    EntryVariant::Message,
    EntryVariant::AccessGroup,
];

const RC_FILE: &str = ".config/message_board/client_rc.toml";

fn extract_name(entry_id: u64, entry: &Entry) -> String {
    #[allow(unreachable_patterns)]
    match &entry.entry_data {
        EntryData::AccessGroup { name, write_perms: _, read_perms: _ } => name.clone(),
        EntryData::Message { timestamp: _, message: _ } => format!("{:016X}", entry_id),
        _ => entry_id.to_string(),
    }
}

struct PathManager {
    path: Vec<(u64, String)>
}

impl PathManager {
    fn new() -> Self {
        Self {
            path: Vec::new(),
        }
    }

    fn is_init(&self) -> bool {
        self.path.len() > 0
    }

    fn peek(&self) -> &(u64, String) {
        if self.path.len() == 0 {panic!("can't peek an uninitialized path")}
        &self.path[self.path.len() -1]
    }

    fn pop(&mut self) -> Option<(u64, String)> {
        // do not remove the root
        if self.path.len() > 1 {
            self.path.pop()
        } else {
            None
        }
    }

    fn push(&mut self, entry_id: u64, entry: &Entry) -> Result<(), DataError> {
        let HeaderData { version: _, parent_id, children_ids: _, author_id: _ } = &entry.header_data;
        if self.path.len() > 0 {
            if *parent_id != self.peek().0 {return Err(DataError::NonChild)}
        } else {
            if (*parent_id != ROOT_ID) | (entry_id != ROOT_ID) {return Err(DataError::MalformedRoot)}
        }

        let name = extract_name(entry_id, entry);
        self.path.push((entry_id, name));
        Ok(())
    }
}

impl Widget for &PathManager {
    fn render(self, area: Rect, buf: &mut Buffer) where Self: Sized {
        let block = Block::bordered()
            .title(" Path ");

        let mut path = Line::default();
        path.push_span(&self.path[0].1);
        for (_id, name) in &self.path[1..] {
            path.push_span("/".bold());
            path.push_span(name);
        }

        Paragraph::new(path)
            .block(block)
            .render(area, buf);
    }
}

struct Selector<T> {
    cursor_pos: Option<usize>,
    items: Vec<T>,
}

impl<T> Selector<T> {
    fn new(items: Vec<T>) -> Self {
        Self {
            cursor_pos: None,
            items
        }
    }

    fn replace_items(&mut self, items: Vec<T>) {
        self.items = items;
        if let Some(cursor_pos) = self.cursor_pos {
            self.cursor_pos = Some(cursor_pos.min(self.items.len()));
        }
    }

    fn down(&mut self) {
        if let Some(cursor_pos) = &mut self.cursor_pos {
            *cursor_pos += 1;
            *cursor_pos %= self.items.len();
        } else {
            self.cursor_pos = Some(0);
        }
    }
    
    fn up(&mut self) {
        if let Some(cursor_pos) = &mut self.cursor_pos {
            *cursor_pos += self.items.len();
            *cursor_pos -= 1;
            *cursor_pos %= self.items.len();
        } else {
            self.cursor_pos = Some(0);
        }
    }

    fn select(&mut self) {
        if self.cursor_pos.is_none() {
            self.cursor_pos = Some(0);
        }
    }

    fn deselect(&mut self) {
        self.cursor_pos = None;
    }

    fn selection(&self) -> Option<(usize, &T)> {
        if let Some(cursor_pos) = self.cursor_pos {
            Some((cursor_pos, &self.items[cursor_pos]))
        } else {
            None
        }
    }

    fn base_render<'a, U: Into<Line<'a>>, F: Fn(&T) -> &str>(&self, area: Rect, buf: &mut Buffer, title: U, f: F) {
        let block = Block::bordered()
            .title(title);

        let mut text = Text::default();
        for (idx, item) in self.items.iter().enumerate() {
            let mut line = Line::from((f)(item));
            if self.cursor_pos.map_or(false, |cursor_pos| cursor_pos == idx) {
                line = line.bold();
            }
            text.push_line(line);
        }
        
        Paragraph::new(text)
            .block(block)
            .render(area, buf);
    }
}

// for the navigator, its (entry_id, name)
impl Widget for &Selector<(u64, String)> {
    fn render(self, area: Rect, buf: &mut Buffer) where Self: Sized {
        self.base_render(area, buf, " Children ", |x| &x.1 as &str);
    }
}

// for entry type selections
impl Widget for &Selector<EntryVariant> {
    fn render(self, area: Rect, buf: &mut Buffer) where Self: Sized {
        self.base_render(area, buf, " Entry Type Selection ", |x| (*x).as_string());
    }
}

struct EntryViewer {
    entry: Option<Entry>
}

impl EntryViewer {
    fn new() -> Self {
        Self {
            entry: None
        }
    }

    fn add_entry(&mut self, entry: Entry) {
        self.entry = Some(entry);
    }

    fn take_entry(&mut self) -> Option<Entry> {
        self.entry.take()
    }

    fn as_entry(&self) -> &Option<Entry> {
        &self.entry
    }
}

impl Widget for &EntryViewer {
    fn render(self, area: Rect, buf: &mut Buffer) where Self: Sized {
        let block = Block::bordered();
        let inner_area = block.inner(area);
        let mut title = Line::default();
        match &self.entry {
            Some(entry) => {
                match &entry.entry_data {
                    EntryData::Message { timestamp, message } => {
                        title.push_span(" Message by ");
                        title.push_span(format!("{:016X}", entry.header_data.author_id));
                        title.push_span(" ");

                        Paragraph::new(message as &str).render(inner_area, buf);

                    }
                    EntryData::AccessGroup { name, write_perms, read_perms } => {
                        title.push_span(" Access Group - ");
                        title.push_span(name);
                        title.push_span(" ");
                        let write_read_titles = [String::from(" Write (Base: "), String::from(" Read (Base: ")];
                        let write_read_layout = Layout::horizontal([Constraint::Fill(1), Constraint::Fill(1)]).split(inner_area);
                        for ((perm_set, mut perm_name ), area) in [write_perms, read_perms].iter().copied().zip(write_read_titles).zip(write_read_layout.iter().copied()) {
                            let block = Block::bordered();
                            let perm_set_area = block.inner(area);
                            perm_name.push_str(&perm_set.get_default_base().to_string());
                            perm_name.push_str(") ");
                            match perm_set {
                                DefaultedIdSet::Inherit { whitelist_ids, blacklist_ids } => {
                                    let layout = Layout::horizontal([Constraint::Fill(1), Constraint::Fill(1)]).split(perm_set_area);
                                    let mut whitelist = Text::default();
                                    whitelist.push_line("Whitelisted:");
                                    for id in whitelist_ids {
                                        let mut line = Line::default();
                                        line.push_span(" -  ".bold());
                                        line.push_span(id.to_string());
                                        whitelist.push_line(line);
                                    }
                                    let mut blacklist = Text::default();
                                    blacklist.push_line("Blacklisted:");
                                    for id in blacklist_ids {
                                        let mut line = Line::default();
                                        line.push_span(" -  ".bold());
                                        line.push_span(id.to_string());
                                        blacklist.push_line(line);
                                    }
                                    whitelist.render(layout[0], buf);
                                    blacklist.render(layout[1], buf);
                                }
                                DefaultedIdSet::White { blacklist_ids } => {
                                    let mut blacklist = Text::default();
                                    blacklist.push_line("Blacklisted:");
                                    for id in blacklist_ids {
                                        let mut line = Line::default();
                                        line.push_span(" -  ".bold());
                                        line.push_span(id.to_string());
                                        blacklist.push_line(line);
                                    }
                                    blacklist.render(perm_set_area, buf);
                                }
                                DefaultedIdSet::Black { whitelist_ids } => {
                                    let mut whitelist = Text::default();
                                    whitelist.push_line("Whitelisted:");
                                    for id in whitelist_ids {
                                        let mut line = Line::default();
                                        line.push_span(" -  ".bold());
                                        line.push_span(id.to_string());
                                        whitelist.push_line(line);
                                    }
                                    whitelist.render(perm_set_area, buf);
                                }
                            }
                            block.title(perm_name).render(area, buf);
                        }
                    }
                }
            }
            None => {
                Paragraph::new("No Entry To Display :P").centered().render(inner_area, buf);
            }
        }

        block.title(title).render(area, buf);
    }
}

enum ViewerState {
    Content,
    Navigate,
}

enum ClientState {
    Viewer(ViewerState),
    WriteVarientSelection(Selector<EntryVariant>),
    Blank,
    Error(Vec<DataError>),
}

struct Client {
    terminal: Option<ratatui::DefaultTerminal>,

    state: Vec<ClientState>,
    path: PathManager,
    navigator: Selector<(u64, String)>,
    viewer: EntryViewer,

    stream: TcpStream,
    user_id: Option<u64>,

    exit: bool,
}

impl Client {
    fn new() -> Result<Self, DataError> {
        let user_home = std::env::home_dir().unwrap();
        let mut real_rc_config = user_home.clone();
        real_rc_config.push(RC_FILE);
        let mut stdin = std::io::stdin();
        let mut stdout = std::io::stdout();
        let mut input_buffer = String::new();
        let mut rc_config_result = std::fs::read_to_string(&real_rc_config).map(|str| str.parse::<toml::Table>().expect("The Client Rc was misformatted"));
        if let Err(ref e) = rc_config_result {
            match e.kind() {
                std::io::ErrorKind::NotFound => {
                    print!("Config file does not exist, create a new one? (y/n): ");
                    let _ = stdout.flush();
                    input_buffer.clear();
                    let create = stdin_y_n(&mut stdin, &mut input_buffer);
                    if create {
                        let mut config = toml::Table::new();
                        print!("Please enter the message board's address: ");
                        let _ = stdout.flush();
                        let mut server_address = String::new();
                        let _ = stdin.read_line(&mut server_address);
                        config.insert("address".to_string(), toml::Value::String(server_address.trim().to_string()));
                        config.insert("user_id".to_string(), toml::Value::String("None".to_string()));

                        let mut parent = real_rc_config.clone();
                        parent.pop();
                        let _ = std::fs::create_dir_all(parent);
                        let _ = std::fs::write(real_rc_config, &config.to_string());
                        rc_config_result = Ok(config);
                    } else {
                        panic!("Cannot continue without a config file, terminating the client");
                    }
                }
                _ => panic!("terminating due to non-specifc config file read error: {}", e.kind())
            }
        }
        let rc_config = rc_config_result.unwrap();
        let user_id_val = &rc_config["user_id"];
        let user_id = match user_id_val {
            toml::Value::Integer(id) => Some(*id as u64), //scuff
            toml::Value::String(str) if str == "None" => None,
            _ => {panic!("The client RC file was misformatted")}
        };
        let toml::Value::String(server_address) = &rc_config["address"] else {panic!("The client RC file was misformatted")};

        let mut connected_stream = None;
        while connected_stream.is_none() {
            let stream = TcpStream::connect((server_address as &str, PORT));
            if let Ok(stream) = stream {
                connected_stream = Some(stream);
            } else if let Err(e) = stream {
                println!("Connection failed: {}", e);
            }
        }

        let terminal = ratatui::init();
        let mut client = Self { 
            terminal: Some(terminal),

            state: vec![ClientState::Viewer(ViewerState::Content)],
            path: PathManager::new(),
            navigator: Selector::new(Vec::new()),
            viewer: EntryViewer::new(),

            stream: connected_stream.unwrap(),
            user_id,
            exit: false,
        };
        
        let _ = client.create_user(); // FIXME: should notify in some way if a new one was minted
        let entry = client.get_entry(ROOT_ID)?;
        client.path.push(ROOT_ID, &entry)?;
        client.set_active_entry(entry);

        Ok(client)
    }

    fn edit_config<F: FnOnce(&mut toml::Table)>(&mut self, f: F) {
        let user_home = std::env::home_dir().unwrap();
        let mut real_rc_config = user_home.clone();
        real_rc_config.push(RC_FILE);

        let mut config = std::fs::read_to_string(&real_rc_config)
            .map(|str| str.parse::<toml::Table>().expect("The Server Rc was misformatted")).unwrap();
        f(&mut config);
        let _ = std::fs::write(&real_rc_config, &config.to_string());
    }

    fn send_request(&mut self, request: BoardRequest) -> Result<BoardResponse, DataError> {
        let request = request.into_data()?;
        let _ = self.stream.write_all(&(request.len() as u64).to_le_bytes());
        let _ = self.stream.write_all(&request);
        let mut num_bytes = [0; 8];
        let _ = self.stream.read_exact(&mut num_bytes);
        let num_bytes = u64::from_le_bytes(num_bytes) as usize;
        let mut buffer = vec![0; num_bytes];
        let _ = self.stream.read_exact(&mut buffer);
        BoardResponse::from_data(&buffer)
    }

    fn get_entry(&mut self, entry_id: u64) -> Result<Entry, DataError> {
        let request = BoardRequest::GetEntry { user_id: self.user_id.unwrap(), entry_id };
        let response = self.send_request(request)?;
        let BoardResponse::GetEntry(entry) = response else {return Err(DataError::InternalError)};
        Ok(entry)
    }

    fn write_entry(&mut self, entry: Entry) -> Result<u64, DataError> {
        let request = BoardRequest::AddEntry { user_id: self.user_id.unwrap(), entry: entry };
        let response = self.send_request(request)?;
        let BoardResponse::AddEntry(entry_id) = response else {return Err(DataError::InternalError)};
        Ok(entry_id)
    }

    fn set_active_entry(&mut self, entry: Entry) {
        self.navigator.replace_items(entry.header_data.children_ids.iter().copied().map(|x| (x, x.to_string())).collect()); // temporary
        self.viewer.add_entry(entry);
    }

    fn get_user(&mut self, user_id: u64) -> Result<UserData, DataError> {
        let request = BoardRequest::GetUser { user_id };
        let response = self.send_request(request)?;
        let BoardResponse::GetUser(user) = response else {return Err(DataError::InternalError)};
        Ok(user)
    }

    fn create_user(&mut self) -> Result<bool, DataError> {
        if let Some(_) = self.user_id {return Ok(false)}
        let request = BoardRequest::AddUser;
        let response = self.send_request(request)?;
        let BoardResponse::AddUser(user_id) = response else {return Err(DataError::InternalError)};
        self.user_id = Some(user_id);
        self.edit_config(|config| config["user_id"] = toml::Value::Integer(user_id as i64));
        Ok(true)
    }

    fn mainloop(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        while !self.exit {
            // little scuffed
            let mut term = self.terminal.take().unwrap();
            term.draw(|frame| self.draw(frame))?;
            self.terminal = Some(term);

            self.handle_events()?;
        }
        Ok(())
    }

    fn draw(&self, frame: &mut ratatui::Frame) {
        frame.render_widget(self, frame.area());
    }

    fn handle_events(&mut self) -> std::io::Result<()> {
        match event::read()? {
            Event::Key(key_event) if key_event.kind == KeyEventKind::Press => {
                match key_event.code {
                    KeyCode::Char('c') if key_event.modifiers == KeyModifiers::CONTROL => {
                        self.exit = true;
                    }
                    KeyCode::Esc => {
                        self.state.pop();
                        if self.state.is_empty() {
                            self.exit = true;
                        }
                    }
                    _ => {
                        let old_top_state = self.state.pop().unwrap();
                        let new_top_state = self.stated_handle_key_event(old_top_state, key_event);
                        match &new_top_state {
                            ClientState::Viewer(ViewerState::Content) => {
                                self.navigator.deselect();
                            }
                            ClientState::Viewer(ViewerState::Navigate) => {
                                self.navigator.select();
                            }
                            _ => {}
                        }
                        // mild jank
                        if let ClientState::Blank = new_top_state {} else {
                            self.state.push(new_top_state)
                        }
                    }
                }
            }
            _ => {}
        }
        Ok(())
    }

    fn stated_handle_key_event(&mut self, state: ClientState, key_event: KeyEvent) -> ClientState {
        match state {
            ClientState::Viewer(ref viewer_state) => {
                match (key_event.code, viewer_state) {
                    (KeyCode::Char('w'), _) => {
                        self.state.push(state);
                        let mut selector = Selector::new(Vec::from(ENTRY_VARIANTS));
                        selector.select();
                        return ClientState::WriteVarientSelection(selector);
                    }
                    (KeyCode::Char('H') | KeyCode::Left, _) if key_event.modifiers.contains(KeyModifiers::SHIFT) => {
                        self.path.pop();
                        let entry = self.get_entry(self.path.peek().0).unwrap();
                        self.set_active_entry(entry);
                    }
                    (KeyCode::Char('l') | KeyCode::Right, ViewerState::Content) => {return ClientState::Viewer(ViewerState::Navigate)}
                    (KeyCode::Char('h') | KeyCode::Left, ViewerState::Navigate) => {return ClientState::Viewer(ViewerState::Content)}
                    (KeyCode::Char('k') | KeyCode::Up, ViewerState::Navigate) => {self.navigator.up();}
                    (KeyCode::Char('j') | KeyCode::Down, ViewerState::Navigate) => {self.navigator.down();}
                    (KeyCode::Enter, ViewerState::Navigate) => 'block: {
                        let Some((_, (entry_id, _))) = self.navigator.selection() else {self.navigator.select(); break 'block};
                        let entry_id = *entry_id;
                        let Ok(entry) = self.get_entry(entry_id) else {break 'block}; // needs a more proper error
                        self.path.push(entry_id, &entry).unwrap();
                        self.set_active_entry(entry);
                        return ClientState::Viewer(ViewerState::Content);
                    }
                    _ => {}
                }
                state
            }
            ClientState::WriteVarientSelection(mut selector) => {
                match key_event.code {
                    KeyCode::Char('k') | KeyCode::Up => {selector.up();}
                    KeyCode::Char('j') | KeyCode::Down => {selector.down();}
                    KeyCode::Enter => 'block: {
                        let Some((_, variant)) = selector.selection() else {selector.select(); break 'block};
                        let entry = match variant {
                            EntryVariant::Message => {
                                // boot up vim for the text editor
                                let mut path = std::env::temp_dir();
                                path.push("MessageBoardEntryDraft.txt");
                                let Ok(_) = std::fs::File::create(&path) else {break 'block};
                                self.terminal = None;
                                ratatui::restore();
                                let Ok(mut child) = std::process::Command::new("vim")
                                    .args([&path])
                                    .spawn() else {break 'block};
                                let Ok(_) = child.wait() else {break 'block};
                                self.terminal = Some(ratatui::init());
                                let Ok(message) = std::fs::read_to_string(&path) else {break 'block};
                                let _ = std::fs::remove_file(&path);
                                Some(Entry {
                                    header_data: HeaderData { 
                                        version: ENTRY_FILE_VERSION, 
                                        parent_id: self.path.peek().0, 
                                        children_ids: Vec::new(), 
                                        author_id: self.user_id.unwrap(), 
                                    },
                                    entry_data: EntryData::Message { 
                                        timestamp: std::time::SystemTime::now().duration_since(std::time::SystemTime::UNIX_EPOCH).unwrap().as_secs(), 
                                        message
                                    }
                                })
                            }
                            _ => {
                                None
                            }
                        };
                        if let Some(entry) = entry {
                            let result = self.write_entry(entry);
                            if let Err(e) = result {
                                self.state.push(ClientState::WriteVarientSelection(selector));
                                return ClientState::Error(vec![e]);
                            }
                            return ClientState::Blank;
                        }
                    }
                    _ => {}
                }
                ClientState::WriteVarientSelection(selector)
            }
            ClientState::Error(_) => {
                return ClientState::Blank;
            }
            ClientState::Blank => {
                return ClientState::Blank; //shouldn't get readded in handle events
            }
        }
    }
}

impl Widget for &Client {
    fn render(self, area: Rect, buf: &mut Buffer)where Self: Sized {
        let layout = Layout::vertical([Constraint::Length(2), Constraint::Fill(1)]).split(area);
        {
            let mut title_line = Line::from(" Message Board - User: ");
            title_line.push_span(format!("{:016X}", self.user_id.unwrap()));
            title_line.push_span(" ");
            title_line.centered().render(layout[0], buf);
        }
        let area = layout[1];
        for sub_state in &self.state {
            match sub_state {
                ClientState::Viewer(_) => {
                    let mut layout = Layout::vertical([Constraint::Length(3), Constraint::Fill(1)]).split(area);
                    let path_area = layout[0];
                    layout = Layout::horizontal([Constraint::Fill(4), Constraint::Fill(1)]).split(layout[1]);
                    let content_area = layout[0];
                    let navigator_area = layout[1];

                    Clear.render(area, buf);
                    self.path.render(path_area, buf);
                    self.navigator.render(navigator_area, buf);
                    self.viewer.render(content_area, buf);
                }
                ClientState::WriteVarientSelection(selector) => {
                    let mut layout = Layout::horizontal([Constraint::Fill(1), Constraint::Percentage(50), Constraint::Fill(1)]).split(area);
                    layout = Layout::vertical([Constraint::Fill(1), Constraint::Percentage(50), Constraint::Fill(1)]).split(layout[1]);
                    let selector_popup_area = layout[1];

                    Clear.render(selector_popup_area, buf);
                    selector.render(selector_popup_area, buf);
                }
                ClientState::Blank => {}
                ClientState::Error(errors) => {
                    let mut layout = Layout::horizontal([Constraint::Fill(1), Constraint::Percentage(50), Constraint::Fill(1)]).split(area);
                    layout = Layout::vertical([Constraint::Fill(1), Constraint::Percentage(50), Constraint::Fill(1)]).split(layout[1]);
                    let error_popup_area = layout[1];

                    let block = Block::bordered().title(" Error(s) ");

                    let mut text = Text::default();
                    for error in errors {
                        let line = Line::from(match error {
                            DataError::IncorrectMagicNum => "IncorrectMagicNum",
                            DataError::InsufficientBytes => "InsufficientBytes",
                            DataError::InvalidDiscriminant => "InvalidDiscriminant",
                            DataError::StringError(_) => "StringError",
                            DataError::UnsupportedVersion => "UnsupportedVersion",     

                            DataError::DoesNotExist => "DoesNotExist",
                            DataError::AlreadyExists => "AlreadyExists",
                            DataError::InsufficientPerms => "InsufficientPerms",
                            DataError::BadCredentials => "BadCredentials",

                            DataError::MalformedRoot => "MalformedRoot",
                            DataError::NonChild => "NonChild ",

                            DataError::InternalError => "InternalError",
                            DataError::OOBUsizeConversion => "OOBUsizeConversion",
                        });
                        text.push_line(line);
                    }

                    Clear.render(error_popup_area, buf);
                    Paragraph::new(text).block(block).render(error_popup_area, buf);
                }
            }
        }
        
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        ratatui::restore();
    }
}

fn main() {
    let mut client = Client::new().unwrap();
    let _ = client.mainloop();
}