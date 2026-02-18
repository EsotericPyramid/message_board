use message_board::*;
use ratatui::style::Stylize;
use ratatui::symbols::border;
use std::io::{Read, Write};
use std::net::*;
use ratatui::{
    text::{Line, Text},
    widgets::{Block, Paragraph, Widget},
    layout::Rect,
    buffer::Buffer,
};


struct Client {
    active_entry: Option<(u64, Entry)>,

    stream: Option<TcpStream>,
    user_id: u64,
    exit: bool,
}

impl Client {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let mut client = Self { 
            active_entry: None,

            stream: None,
            user_id: 0,
            exit: false,
        };
        while client.stream.is_none() {
            let stream = TcpStream::connect(String::from("127.0.0.1:") + &PORT.to_string());
            if let Ok(stream) = stream {
                client.stream = Some(stream);
            } else if let Err(e) = stream {
                println!("Connection failed: {}", e);
            }
        }
        if client.active_entry.is_none() {
            let entry = client.get_entry(ROOT_ID).unwrap();
            client.active_entry = Some((ROOT_ID, entry));
        }
        Ok(client)
    }

    fn get_entry(&mut self, entry_id: u64) -> Result<Entry, DataError> {
        if let Some(stream) = &mut self.stream {
            let request = BoardRequest::GetEntry { user_id: self.user_id, entry_id }.into_data();
            let _ = stream.write_all(&(request.len() as u64).to_le_bytes());
            let _ = stream.write_all(&request);
            let mut num_bytes = [0; 8];
            let _ = stream.read_exact(&mut num_bytes);
            let num_bytes = u64::from_le_bytes(num_bytes) as usize;
            let mut buffer = vec![0; num_bytes];
            let _ = stream.read_exact(&mut buffer);
            let BoardResponse::GetEntry(entry) = BoardResponse::from_data(&buffer)? else {return Err(DataError::InternalError)};
            Ok(entry)
        } else {
            Err(DataError::InternalError)
        }
    }

    fn mainloop(&mut self, term: &mut ratatui::DefaultTerminal) -> Result<(), Box<dyn std::error::Error>> {
        while !self.exit {
            term.draw(|frame| self.draw(frame))?;
            self.handle_events();
        }
        Ok(())
    }

    fn draw(&self, frame: &mut ratatui::Frame) {
        frame.render_widget(self, frame.area());
    }

    fn handle_events(&mut self) {
        
    }
}

impl Widget for &Client {
    fn render(self, area: Rect, buf: &mut Buffer)where Self: Sized {
        let title = Line::from(" Message Board Client ".bold());
        let border = Block::bordered()
            .title(title.centered())
            .border_set(border::THICK);
        let contents = match &self.active_entry {
            Some((_id, entry)) => {
                match &entry.entry_data {
                    EntryData::Message { timestamp, message } => message,
                    EntryData::AccessGroup { name, access_base, whitelist_ids, blacklist_ids } => name,
                }
            }
            None => {
                " No entry loaded to render or board to navigate :P"
            }
        };

        Paragraph::new(contents)
            .centered()
            .block(border)
            .render(area, buf);
    }
}

fn main() {
    ratatui::run(|terminal| {
        let mut client = Client::new().unwrap();
        let _ = client.mainloop(terminal);
    });

    
}