#![allow(unused_results)]

use crossterm::event::{self, Event, KeyCode, KeyModifiers};
use message_board::*;
use ratatui::layout::{Constraint, Layout};
use ratatui::style::Stylize;
use ratatui::widgets::{Clear};
use std::io::Write;
use ratatui::{
    text::{Line, Text},
    widgets::{Block, Paragraph, Widget},
    layout::Rect,
    buffer::Buffer,
};
use std::cell::RefCell;
use std::rc::Rc;
use message_board::utils::*;
use message_board::internal_error;

const ENTRY_VARIANTS: [EntryVariant; 2] = [
    EntryVariant::Message,
    EntryVariant::AccessGroup,
];

    
const RC_FILE: &str = ".config/message_board/client_rc.toml";
    
mod client_libs;
use client_libs::utils::*;
use client_libs::base_widgets::*;


struct Config {
    user_id: Option<u64>,
    server_address: String,
}

impl Config {
    fn from_toml(config_toml: &toml::Table) -> Self {
        let user_id_val = &config_toml["user_id"];
        let user_id = match user_id_val {
            toml::Value::Integer(id) => Some(*id as u64), //scuff
            toml::Value::String(str) if str == "None" => None,
            _ => {panic!("The client RC file was misformatted")}
        };
        let toml::Value::String(server_address) = &config_toml["address"] else {panic!("The client RC file was misformatted")};
        Config { user_id, server_address: server_address.clone() }
    }

    fn into_toml(self) -> toml::Table {
        let mut config_toml = toml::Table::new();
        let user_id = match self.user_id {
            Some(id) => toml::Value::Integer(id as i64),
            None => toml::Value::String(String::from("None")),
        };
        config_toml.insert(String::from("user_id"), user_id);
        config_toml.insert(String::from("address"), toml::Value::String(self.server_address));
        config_toml
    }
}

fn edit_config<F: FnOnce(&mut Config)>(f: F) {
    let user_home = std::env::home_dir().unwrap();
    let mut real_rc_config = user_home.clone();
    real_rc_config.push(RC_FILE);
    let mut config = Config::from_toml(&std::fs::read_to_string(&real_rc_config)
        .map(|str| str.parse::<toml::Table>().expect("The Server Rc was misformatted")).unwrap());
    f(&mut config);
    let _ = std::fs::write(&real_rc_config, &config.into_toml().to_string());
}

fn get_config() -> Config {
    let user_home = std::env::home_dir().unwrap();
    let mut real_rc_config = user_home.clone();
    real_rc_config.push(RC_FILE);
    Config::from_toml(&std::fs::read_to_string(&real_rc_config)
        .map(|str| str.parse::<toml::Table>().expect("The Server Rc was misformatted")).unwrap())
}

fn validate_config() {
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
    let _ = Config::from_toml(&rc_config);
}




fn extract_name(entry_id: u64, entry: &Entry) -> String {
    #[allow(unreachable_patterns)]
    match &entry.entry_data {
        EntryData::AccessGroup { name, write_perms: _, read_perms: _ } => name.clone(),
        EntryData::Message { timestamp: _, message: _ } => format!("{:016X}", entry_id),
        _ => entry_id.to_string(),
    }
}


#[derive(Debug)]
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

    fn peek(&self) -> Option<&(u64, String)> {
        if self.path.len() == 0 {return None}
        Some(&self.path[self.path.len() -1])
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
            if *parent_id != self.peek().unwrap().0 {return Err(DataError::NonChild)}
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


#[derive(Debug)]
struct Navigator(ScrollContainer<(u64, String)>);

impl Navigator {
    fn replace_items(&mut self, items: &[u64]) {
        self.0.replace_items(items.iter().copied().map(|x| (x, format!("{:016X}", x))).collect())
    }
}

impl InputWidget for Navigator {
    fn render(&self, area: Rect, buf: &mut Buffer) -> Rect {
        self.0.base_render(area, buf, " Children ", |x| x.1.clone())
    }

    fn handle_event(&mut self, event: Event) -> Option<StateChange> {
        if let Some(event) = self.0.base_handle_event(event.clone()) {
            return Some(event)
        } else {
            if let Event::Key(key_event) = event {
                if !key_event.is_press() {return None}
                match key_event.code {
                    KeyCode::Enter => {
                        return Some(StateChange::Pop)
                    }
                    _ => {}
                }
            }
            None
        }
    }

    fn focus(&mut self) {self.0.focus();}
    fn unfocus(&mut self) {self.0.unfocus();}

    fn consume_child(&mut self, child: ClientState) -> Option<StateChange> {
        if let ClientState::Blank | ClientState::Error(_) = child {} else {
            eprintln!("unexpected child of Naviagator")
        }
        None
    }
}

#[derive(Debug)]
struct EntryVariantSelector(ScrollContainer<EntryVariant>);

impl EntryVariantSelector {
    fn new() -> Self {
        Self(ScrollContainer::new(Vec::from(ENTRY_VARIANTS)))
    }
}

impl InputWidget for EntryVariantSelector {
    fn render(&self, area: Rect, buf: &mut Buffer) -> Rect {
        self.0.base_render(area, buf, " Entry Type Selection ", |x| String::from((*x).as_string()))
    }

    fn handle_event(&mut self, event: Event) -> Option<StateChange> {
        if let Some(event) = self.0.base_handle_event(event.clone()) {
            return Some(event)
        } else {
            if let Event::Key(key_event) = event {
                if !key_event.is_press() {return None}
                match key_event.code {
                    KeyCode::Enter => {
                        return Some(StateChange::Pop)
                    }
                    _ => {}
                }
            }
            None
        }
    }

    fn focus(&mut self) {self.0.focus();}
    fn unfocus(&mut self) {self.0.unfocus();}

    fn consume_child(&mut self, child: ClientState) -> Option<StateChange> {
        if let ClientState::Blank | ClientState::Error(_) = child {} else {
            eprintln!("unexpected child of EntryVariantSelector")
        }
        None
    }
}

#[derive(Debug)]
struct IdList {
    container: ScrollContainer<u64>,
}

impl IdList {
    fn new(ids: Vec<u64>) -> Self {
        Self {
            container: ScrollContainer::new(ids),
        }
    }
}


impl InputWidget for IdList {
    fn render(&self, area: Rect, buf: &mut Buffer) -> Rect {
        self.container.base_render(area, buf, " id list (temp name) ", |x| format!("{:016X}", x))
    }
    
    fn handle_event(&mut self, event: Event) -> Option<StateChange> {
        if let Some(event) = self.container.base_handle_event(event.clone()) {
            return Some(event)
        } else {
            if let Event::Key(key_event) = event {
                if !key_event.is_press() {return None}
                match key_event.code {
                    KeyCode::Char('w') => {
                        return Some(StateChange::Push(ClientState::TextEntry(TextEntry::new(16))));
                    }
                    KeyCode::Char('d') | KeyCode::Backspace => {
                        self.container.remove();
                        return Some(StateChange::Blank);
                    }
                    _ => {}
                }
            }
        }
        None
    }

    fn focus(&mut self) {
        self.container.focus();
    }
    fn unfocus(&mut self) {
        self.container.unfocus();
        //self.id_entry.unfocus();
    }

    fn consume_child(&mut self, child: ClientState) -> Option<StateChange> {
        match child {
            ClientState::TextEntry(text_entry) => {
                let Ok(new_id) = u64::from_str_radix(&text_entry.text.iter().collect::<String>(), 16) else {
                    return Some(StateChange::Push(ClientState::Error(vec![internal_error!()])));
                };
                if !self.container.items.contains(&new_id) {self.container.push(new_id)}
                return Some(StateChange::Blank);
            }
            ClientState::Blank | ClientState::Error(_) => {}
            _ => {eprintln!("unexpected child of Naviagator")}
        }
        None
    }
}




#[derive(Debug)]
struct EntryViewer {
    entry: Option<Entry>,
    has_mutated: bool,
    x_select: usize,
    y_select: usize,
    x_size: usize,
    y_size: usize,

    is_focused: bool,
}

impl EntryViewer {
    fn new() -> Self {
        Self {
            entry: None,
            has_mutated: false,
            x_select: 0,
            y_select: 0,
            x_size: 0,
            y_size: 0,

            is_focused: false,
        }
    }

    #[must_use]
    fn add_entry(&mut self, entry: Entry) -> Option<Entry> {
        match &entry.entry_data {
            EntryData::Message { .. } => {
                self.x_select = 0;
                self.y_select = 0;
                self.x_size = 1;
                self.y_size = 1;
            }
            EntryData::AccessGroup { write_perms, read_perms, .. } => {
                self.x_select = 0;
                self.y_select = 0;
                self.x_size = 2;
                self.y_size = 1;
                if let DefaultedIdSet::Inherit { .. } = write_perms {self.x_size += 1};
                if let DefaultedIdSet::Inherit { .. } = read_perms  {self.x_size += 1};
            }
        }
        let out = if self.has_mutated {
            self.take_entry()
        } else {
            None
        };
        self.entry = Some(entry);
        self.has_mutated = false;
        out
    }

    fn take_entry(&mut self) -> Option<Entry> {
        self.has_mutated = false;
        self.entry.take()
    }

    fn as_entry(&self) -> &Option<Entry> {
        &self.entry
    }

    fn as_entry_mut(&mut self) -> &mut Option<Entry> {
        if let Some(_) = self.entry {self.has_mutated |= true;}
        &mut self.entry
    }
}

impl InputWidget for EntryViewer {
    fn render(&self, area: Rect, buf: &mut Buffer) -> Rect {
        let block = Block::bordered();
        let inner_area = block.inner(area);
        let mut title = Line::default();
        let sub_area = match &self.entry {
            Some(entry) => {
                match &entry.entry_data {
                    EntryData::Message { timestamp, message } => {
                        title.push_span(" Message by ");
                        title.push_span(format!("{:016X}", entry.header_data.author_id));
                        title.push_span(", written/editted ");
                        title.push_span(chrono::DateTime::from_timestamp_secs(*timestamp as i64).unwrap().to_string());
                        title.push_span(" ");

                        Paragraph::new(message as &str).render(inner_area, buf);
                        area
                    }
                    EntryData::AccessGroup { name, write_perms, read_perms } => {
                        title.push_span(" Access Group - ");
                        title.push_span(name);
                        title.push_span(" ");
                        let write_read_titles = [String::from(" Write (Base: "), String::from(" Read (Base: ")];
                        let write_read_layout = Layout::horizontal([Constraint::Fill(1), Constraint::Fill(1)]).split(inner_area);
                        let mut x = 0;
                        let mut sub_area = area;
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
                                    if (self.x_select == x) & self.is_focused {whitelist = whitelist.bold(); sub_area = layout[0]}
                                    x += 1;
                                    for id in whitelist_ids {
                                        let mut line = Line::default();
                                        line.push_span(" -  ".bold());
                                        line.push_span(format!("{:016X}", id));
                                        whitelist.push_line(line);
                                    }
                                    let mut blacklist = Text::default();
                                    blacklist.push_line("Blacklisted:");
                                    if (self.x_select == x) & self.is_focused {blacklist = blacklist.bold(); sub_area = layout[1]}
                                    x += 1;
                                    for id in blacklist_ids {
                                        let mut line = Line::default();
                                        line.push_span(" -  ".bold());
                                        line.push_span(format!("{:016X}", id));
                                        blacklist.push_line(line);
                                    }
                                    whitelist.render(layout[0], buf);
                                    blacklist.render(layout[1], buf);
                                }
                                DefaultedIdSet::White { blacklist_ids } => {
                                    let mut blacklist = Text::default();
                                    blacklist.push_line("Blacklisted:");
                                    if (self.x_select == x) & self.is_focused {blacklist = blacklist.bold(); sub_area = perm_set_area}
                                    x += 1;
                                    for id in blacklist_ids {
                                        let mut line = Line::default();
                                        line.push_span(" -  ".bold());
                                        line.push_span(format!("{:016X}", id));
                                        blacklist.push_line(line);
                                    }
                                    blacklist.render(perm_set_area, buf);
                                }
                                DefaultedIdSet::Black { whitelist_ids } => {
                                    let mut whitelist = Text::default();
                                    whitelist.push_line("Whitelisted:");
                                    if (self.x_select == x) & self.is_focused {whitelist = whitelist.bold(); sub_area = perm_set_area}
                                    x += 1;
                                    for id in whitelist_ids {
                                        let mut line = Line::default();
                                        line.push_span(" -  ".bold());
                                        line.push_span(format!("{:016X}", id));
                                        whitelist.push_line(line);
                                    }
                                    whitelist.render(perm_set_area, buf);
                                }
                            }
                            block.title(perm_name).render(area, buf);
                        }
                        sub_area
                    }
                }
            }
            None => {
                Paragraph::new("No Entry To Display :P").centered().render(inner_area, buf);
                area
            }
        };

        block.title(title).render(area, buf);
        sub_area
    }

    fn handle_event(&mut self, event: Event) -> Option<StateChange> {
        if let Some(entry) = &mut self.entry {
            //universal stuff
            if let Event::Key(key_event) = event.clone() {
                let mut matched = true;
                match key_event.code {
                    left!() => {
                        if self.x_select == 0 {
                            return Some(StateChange::MoveLeft)
                        } else {
                            self.x_select -= 1;
                        }
                    }
                    up!() => {
                        if self.y_select == 0 {
                            return Some(StateChange::MoveUp)
                        } else {
                            self.y_select -= 1;
                        }
                    }
                    down!() => {
                        self.y_select += 1;
                        if self.y_select >= self.y_size {
                            self.y_select = self.y_size -1;
                            return Some(StateChange::MoveDown)
                        }
                    }
                    right!() => {
                        self.x_select += 1;
                        if self.x_select >= self.x_size {
                            self.x_select = self.x_size -1;
                            return Some(StateChange::MoveRight)
                        }
                    }
                    _ => {matched = false}
                }
                if matched {return Some(StateChange::Blank)}
            }
            match &mut entry.entry_data {
                EntryData::Message { .. } => {}
                EntryData::AccessGroup { write_perms, read_perms, .. } => {
                    if let Event::Key(key_event) = event {
                        match key_event.code {
                            KeyCode::Enter => {
                                let mut id_lists = Vec::new();
                                for perm_set in [write_perms, read_perms] {
                                    match perm_set {
                                        DefaultedIdSet::Inherit { whitelist_ids, blacklist_ids } => {
                                            id_lists.push(whitelist_ids);
                                            id_lists.push(blacklist_ids);
                                        }
                                        DefaultedIdSet::Black { whitelist_ids } => {
                                            id_lists.push(whitelist_ids);
                                        }
                                        DefaultedIdSet::White { blacklist_ids } => {
                                            id_lists.push(blacklist_ids);
                                        }
                                    }
                                }
                                return Some(
                                    StateChange::Push(
                                        ClientState::AccessGroupIdList(
                                            AccessGroupIdList { 
                                                id_list: IdList::new(id_lists[self.x_select].clone()), 
                                                idx: self.x_select 
                                            }
                                        )
                                    )
                                )
                            }
                            _ => {}
                        }
                    }
                }
            }
        }
        None
    }

    fn focus(&mut self) {self.is_focused = true}
    fn unfocus(&mut self) {self.is_focused = false}

    fn consume_child(&mut self, child: ClientState) -> Option<StateChange> {
        if let Some(entry) = &mut self.entry {
            match (&mut entry.entry_data, child) {
                (EntryData::AccessGroup { name: _, write_perms, read_perms }, ClientState::AccessGroupIdList(access_group_list)) => {
                    let mut id_lists = Vec::new();
                    for perm_set in [write_perms, read_perms] {
                        match perm_set {
                            DefaultedIdSet::Inherit { whitelist_ids, blacklist_ids } => {
                                id_lists.push(whitelist_ids);
                                id_lists.push(blacklist_ids);
                            }
                            DefaultedIdSet::Black { whitelist_ids } => {
                                id_lists.push(whitelist_ids);
                            }
                            DefaultedIdSet::White { blacklist_ids } => {
                                id_lists.push(blacklist_ids);
                            }
                        }
                    }
                    if id_lists[access_group_list.idx] != &access_group_list.id_list.container.items {
                        self.has_mutated = true;
                        let _ = std::mem::replace(id_lists[access_group_list.idx],access_group_list.id_list.container.items);
                    }
                }
                (_, ClientState::Blank | ClientState::Error(_)) => {}
                _ => eprintln!("Unexpected child of EntryViewer"),
            }
        } else {
            if let ClientState::Blank | ClientState::Error(_) = child {} else {
                eprintln!("Unexpected child of EntryViewer")
            }
        }
        None
    }
}


#[derive(Debug, Clone, Copy)]
enum TreeViewerState {
    Content,
    Navigate,
    Unfocused
}

#[derive(Debug)]
struct EntryTreeViewer {
    path: PathManager,
    navigator: Navigator,
    viewer: EntryViewer,
    state: TreeViewerState,
    awaited_child_parent: Option<TreeViewerState>, //janked type
    
    board: Rc<RefCell<MessageBoardConnection>>,
    terminal: Rc<RefCell<Terminal>>,
}

impl EntryTreeViewer {
    fn new(board: Rc<RefCell<MessageBoardConnection>>, terminal: Rc<RefCell<Terminal>>) -> Result<Self, DataError> {
        let mut viewer = Self {
            path: PathManager::new(),
            navigator: Navigator (ScrollContainer::new(Vec::new())),
            viewer: EntryViewer::new(),
            state: TreeViewerState::Unfocused,
            awaited_child_parent: None,

            board,
            terminal,
        };

        viewer.push_active_entry(ROOT_ID)?; // FIXME: scuff, really there is no "last" entry_id

        Ok(viewer)
    }

    fn reload(&mut self) -> Result<(), DataError> {
        let new_id = self.path.peek().unwrap().0;
        self.swap_active_entry(new_id)?;
        if new_id == ROOT_ID {self.path.pop();} //scuff
        Ok(())
    }

    fn swap_active_entry(&mut self, new_entry_id: u64) -> Result<(), DataError> {
        let mut board = self.board.borrow_mut();
        let new_entry = board.get_entry(new_entry_id)?;
        self.navigator.replace_items(&new_entry.header_data.children_ids); // temporary
        let old_entry_id = self.path.peek().map(|x| x.0); //jank
        self.path.pop();
        self.path.push(new_entry_id, &new_entry)?;
        if let (Some(old_entry), Some(old_entry_id)) = (self.viewer.add_entry(new_entry), old_entry_id) {
            board.edit_entry(old_entry_id, old_entry)?;
        }
        Ok(())
    }

    fn push_active_entry(&mut self, new_entry_id: u64) -> Result<(), DataError> {
        let mut board = self.board.borrow_mut();
        let new_entry = board.get_entry(new_entry_id)?;
        self.navigator.replace_items(&new_entry.header_data.children_ids); // temporary
        let old_entry_id = self.path.peek().map(|x| x.0); //jank
        self.path.push(new_entry_id, &new_entry)?;
        if let (Some(old_entry), Some(old_entry_id)) = (self.viewer.add_entry(new_entry), old_entry_id) {
            board.edit_entry(old_entry_id, old_entry)?;
        }
        Ok(())
    }

    fn pop_active_entry(&mut self) -> Result<(), DataError> {
        self.path.pop();
        self.reload()
    }

    fn set_state(&mut self, state: TreeViewerState) {
        match state {
            TreeViewerState::Content => {
                self.viewer.focus();
                self.navigator.unfocus();
            }
            TreeViewerState::Navigate => {
                self.viewer.unfocus();
                self.navigator.focus();
            }
            TreeViewerState::Unfocused => {
                self.viewer.unfocus();
                self.navigator.unfocus();
            }
        }
        self.state = state;
    }
}

impl Drop for EntryTreeViewer {
    fn drop(&mut self) {
        if self.viewer.has_mutated {
            if let Some(entry) = self.viewer.take_entry() {
                if let Some((id, _)) = self.path.peek() {
                    let _ = self.board.borrow_mut().edit_entry(*id, entry);
                }
            }
        }
    }
}

impl InputWidget for EntryTreeViewer {
    fn render(&self, area: Rect, buf: &mut Buffer) -> Rect {
        let mut layout = Layout::vertical([Constraint::Length(3), Constraint::Fill(1)]).split(area);
        let path_area = layout[0];
        layout = Layout::horizontal([Constraint::Fill(4), Constraint::Fill(1)]).split(layout[1]);
        let content_area = layout[0];
        let navigator_area = layout[1];

        Clear.render(area, buf);
        self.path.render(path_area, buf);
        let navigator_sub_area = self.navigator.render(navigator_area, buf);
        let content_sub_area = self.viewer.render(content_area, buf);
        eprintln!("EntryTreeViewer: {:?}", content_sub_area);
        let mut matched_state = self.state;
        if let TreeViewerState::Unfocused = matched_state {matched_state = self.awaited_child_parent.unwrap_or(TreeViewerState::Unfocused)}
        match matched_state {
            TreeViewerState::Unfocused => area,
            TreeViewerState::Content => content_sub_area,
            TreeViewerState::Navigate => navigator_sub_area,
        }
    }

    fn handle_event(&mut self, event: Event) -> Option<StateChange> {
        let mut matched = false;
        if let Event::Key(key_event) = event.clone() {
            matched = true;
            self.awaited_child_parent = Some(TreeViewerState::Unfocused);            
            match key_event.code {
                KeyCode::Char('H') if key_event.modifiers.contains(KeyModifiers::SHIFT) => {
                    if let Err(e) = self.pop_active_entry() {
                        return Some(StateChange::Push(ClientState::Error(vec![e])));
                    }
                }
                KeyCode::Char('w') => {
                    return Some(StateChange::Push(ClientState::WriteVarientSelection(EntryVariantSelector::new())))
                }
                _ => matched = false
            }
        }
        if matched {return Some(StateChange::Blank)}
        match self.state {
            TreeViewerState::Content => {
                self.awaited_child_parent = Some(TreeViewerState::Content);
                if let Some(state_change) = self.viewer.handle_event(event) {
                    match state_change {
                        StateChange::MoveRight => {self.set_state(TreeViewerState::Navigate);},
                        other => return Some(other)
                    }
                }
            },
            TreeViewerState::Navigate => {
                self.awaited_child_parent = Some(TreeViewerState::Navigate);
                if let Some(state_change) = self.navigator.handle_event(event) {
                    match state_change {
                        StateChange::Pop => {
                            let new_entry_id = self.navigator.0.selection().unwrap().1.0;
                            if let Err(e) = self.push_active_entry(new_entry_id) {return Some(StateChange::Push(ClientState::Error(vec![e])))};
                            return Some(StateChange::Blank);
                        },
                        StateChange::MoveLeft => {self.set_state(TreeViewerState::Content);},
                        other => return Some(other)
                    }
                }
            },
            TreeViewerState::Unfocused => panic!("EntryTreeViewer shouldn't handle events while unfocused")
        }
        self.awaited_child_parent = None;
        None
    }

    fn focus(&mut self) {
        if let TreeViewerState::Unfocused = self.state {self.state = TreeViewerState::Content}
    }

    fn unfocus(&mut self) {
        self.state = TreeViewerState::Unfocused;
    }

    fn consume_child(&mut self, child: ClientState) -> Option<StateChange> {
        let Some(child_parent) = &self.awaited_child_parent else {
            eprintln!("Unexpected child of EntryTreeViewer");
            return None;
        };
        match child_parent {
            TreeViewerState::Unfocused => {
                let mut matched = true;
                match child {
                    ClientState::WriteVarientSelection(selector) => {
                        let header = HeaderData { 
                            version: ENTRY_FILE_VERSION, 
                            parent_id: self.path.peek().unwrap().0, 
                            children_ids: Vec::new(), 
                            author_id: self.board.borrow().get_user_id().unwrap(), 
                        };
                        let entry = match selector.0.selection().unwrap().1 {
                            EntryVariant::Message => {
                                // boot up vim for the text editor
                                let mut path = std::env::temp_dir();
                                path.push("MessageBoardEntryDraft.txt");
                                let Ok(_) = std::fs::File::create(&path) else {return Some(StateChange::Push(ClientState::Error(vec![internal_error!()])))};
                                if let Err(e) = self.terminal.borrow_mut().pause(|| {
                                    ratatui::restore();
                                    let Ok(mut child) = std::process::Command::new("vim")
                                        .args([&path])
                                        .spawn() else {return Err(internal_error!())};
                                    let Ok(_) = child.wait() else {return Err(internal_error!())};
                                    Ok(())
                                }) {
                                    return Some(StateChange::Push(ClientState::Error(vec![e])))
                                };
                                let Ok(message) = std::fs::read_to_string(&path) else {return Some(StateChange::Push(ClientState::Error(vec![internal_error!()])))};
                                let _ = std::fs::remove_file(&path);
                                Some(Entry {
                                    header_data: header,
                                    entry_data: EntryData::Message { 
                                        timestamp: std::time::SystemTime::now().duration_since(std::time::SystemTime::UNIX_EPOCH).unwrap().as_secs(), 
                                        message
                                    }
                                })
                            }
                            EntryVariant::AccessGroup => {
                                Some(Entry {
                                    header_data: header,
                                    entry_data: EntryData::AccessGroup { 
                                        name: String::from("test"), 
                                        write_perms: DefaultedIdSet::Inherit { whitelist_ids: Vec::new(), blacklist_ids: Vec::new() }, 
                                        read_perms: DefaultedIdSet::Inherit { whitelist_ids: Vec::new(), blacklist_ids: Vec::new() },
                                    }
                                })
                            }
                        };
                        if let Some(entry) = entry {
                            let result = self.board.borrow_mut().write_entry(entry);
                            if let Err(e) = result {
                                return Some(StateChange::Push(ClientState::Error(vec![e])));
                            }
                        }
                    }
                    ClientState::Blank | ClientState::Error(_) => {}
                    _ => matched = false,
                }
                if matched {Some(StateChange::Blank)} else {None}
            }
            TreeViewerState::Content => self.viewer.consume_child(child),
            TreeViewerState::Navigate => self.navigator.consume_child(child),
        }
    }
}


#[derive(Debug)]
struct AccessGroupIdList {
    id_list: IdList, 
    idx: usize,
}

impl InputWidget for AccessGroupIdList {
    fn render(&self, area: Rect, buf: &mut Buffer) -> Rect {self.id_list.render(area, buf)}
    fn handle_event(&mut self, event: Event) -> Option<StateChange> {self.id_list.handle_event(event)}
    fn focus(&mut self) {self.id_list.focus();}
    fn unfocus(&mut self) {self.id_list.unfocus();}
    fn consume_child(&mut self, child: ClientState) -> Option<StateChange> {self.id_list.consume_child(child)}
}


#[derive(Debug)]
struct Client {
    terminal: Rc<RefCell<Terminal>>,
    board: Rc<RefCell<MessageBoardConnection>>,
    
    state: Vec<ClientState>,
    exit: bool,
}

impl Client {
    fn new() -> Result<Self, DataError> {
        validate_config();
        let config = get_config();

        let board = Rc::new(RefCell::new(MessageBoardConnection::new(&config)));
        let terminal = Rc::new(RefCell::new(Terminal::new()));
        
        let mut client = Self { 
            terminal: terminal.clone(),
            board: board.clone(),
            
            state: Vec::new(),
            exit: false,
        };
        client.handle_state_change(Some(StateChange::Push(ClientState::Viewer(EntryTreeViewer::new(board, terminal)?))));
        Ok(client)
    }

    fn handle_state_change(&mut self, change: Option<StateChange>) {
        eprintln!("{:?}", change);
        if let Some(change) = change {
            match change {
                StateChange::Push(mut new_state) => {
                    if self.state.len() > 0 {
                        let state_end = self.state.len() -1;
                        self.state[state_end].unfocus();
                    }
                    if let ClientState::Blank = new_state {return}
                    new_state.focus();
                    self.state.push(new_state);
                }
                StateChange::Pop => {
                    let child_state = self.state.pop().expect("Shouldn't pop off a state when there are no states");
                    if self.state.len() > 0 {
                        let state_end = self.state.len() -1; // aside: lifetimes are cool but sometimes they are just feel dumb :(
                        self.state[state_end].consume_child(child_state);
                        self.state[state_end].focus();
                    }
                }
                StateChange::Swap(new_state) => {
                    if let ClientState::Blank = new_state {
                        self.handle_state_change(Some(StateChange::Pop));
                    } else {
                        // NOTE: can't swap this out for the `handle_state_change` to avoid termination if only 1 state on the stack
                        let child_state = self.state.pop().expect("Shouldn't pop off a state when there are no states");
                        if self.state.len() > 0 {
                            let state_end = self.state.len() -1; // aside: lifetimes are cool but sometimes they are just feel dumb :(
                            self.state[state_end].consume_child(child_state);
                            self.state[state_end].focus();
                        }
                        self.handle_state_change(Some(StateChange::Push(new_state)));
                    }
                }
                _ => {}
            }
        }
        if self.state.len() == 0 {self.exit = true; return}
    }

    fn mainloop(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        while !self.exit {
            self.terminal.borrow_mut().draw(|frame| self.draw(frame))?;

            self.handle_events()?;
        }
        
        Ok(())
    }

    fn draw(&self, frame: &mut ratatui::Frame) {
        frame.render_widget(self, frame.area());
    }

    fn handle_events(&mut self) -> std::io::Result<()> {
        let event = event::read()?;
        let mut matched = true;
        if let Event::Key(key_event) = event.clone() {
            if key_event.is_press() {
                match key_event.code {
                    KeyCode::Char('c') if key_event.modifiers.contains(KeyModifiers::CONTROL) => self.exit = true,
                    KeyCode::Esc => {
                        self.handle_state_change(Some(StateChange::Pop));
                    }
                    _ => matched = false
                }
            }
        }
        if !matched {
            let end = self.state.len() -1;
            let state_change = (&mut self.state[end]).handle_event(event);
            self.handle_state_change(state_change);
        }
        Ok(())
    }
}

impl Widget for &Client {
    fn render(self, area: Rect, buf: &mut Buffer)where Self: Sized {
        let layout = Layout::vertical([Constraint::Length(2), Constraint::Fill(1)]).split(area);
        {
            let title_line = Line::from(" Message Board - by EsotericPyramid ");
            title_line.centered().render(layout[0], buf);
        }
        let mut area = layout[1];
        for sub_state in &self.state {
            eprintln!("{:?}", sub_state);
            area = sub_state.render(area, buf);
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