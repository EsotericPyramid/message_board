use message_board::*;
use termwiz::terminal::Terminal;
use std::io::{Read, Write};
use std::net::*;
use std::rc::Rc;
use std::sync::mpsc;
use termwiz::surface::{Surface, Change, Position, SequenceNo};
use termwiz::widgets::Widget;

/// just views an entry's content (not the header)
struct EntryViewer {
    entry: Option<Entry>,
    rx: mpsc::Receiver<Option<Entry>>
}

impl EntryViewer {
    fn new(rx: mpsc::Receiver<Option<Entry>>) -> Self {
        Self { 
            entry: None,
            rx
        }
    }
}

impl Widget for EntryViewer {
    fn render(&mut self, args: &mut termwiz::widgets::RenderArgs) {
        if let Some(new_entry) = self.rx.try_iter().last() {
            self.entry = new_entry;
        }
        match &self.entry {
            Some(Entry { entry_data, header_data }) => {
                match entry_data {
                    EntryData::Message { timestamp, message } => {todo!()}
                    EntryData::AccessGroup { name, access_base, whitelist_ids, blacklist_ids } => {
                        args.surface.add_changes(vec![
                            Change::CursorPosition { x: Position::Absolute(0), y: Position::Absolute(0) },
                            Change::Text(name.to_string()),
                            Change::CursorPosition { x: Position::Absolute(0), y: Position::Absolute(3) },
                            Change::Text(match access_base {
                                AccessBase::Inherit => "Inherit".to_string(),
                                AccessBase::White => "White".to_string(),
                                AccessBase::Black => "Black".to_string(),
                            }),
                            Change::CursorPosition { x: Position::Absolute(0), y: Position::Absolute(4) },
                        ]);
                    }
                }
            }
            None => {
                args.surface.add_changes(vec![Change::Text("No selected entry to display :P".to_string()), Change::CursorPosition { x: Position::Absolute(0), y: Position::Absolute(0) }]);
            }
        }
    }
}

struct Client<'a> {
    term: Box<dyn Terminal>,
    screen: Surface,
    seq_num: SequenceNo,
    ui: termwiz::widgets::Ui<'a>,
    root_widget: termwiz::widgets::WidgetId,
    entry_viewer: mpsc::Sender<Option<Entry>>,

    stream: Option<TcpStream>,
    user_id: u64,
}

impl<'a> Client<'a> {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let term_caps = termwiz::caps::Capabilities::new_from_env()?;
        let mut term = termwiz::terminal::new_terminal(term_caps)?;
        let size = term.get_screen_size()?;
        let screen = Surface::new(size.cols, size.rows);

        let mut ui = termwiz::widgets::Ui::new();
        let (tx, rx) = mpsc::channel();
        let root_widget = ui.set_root(EntryViewer::new(rx));
        Ok(Self { 
            term: Box::new(term),
            screen,
            seq_num: 0,
            ui,
            root_widget,
            entry_viewer: tx,

            stream: None,
            user_id: 0,
        })
    }

    fn mainloop(&mut self) {
        let mut flag = false;
        loop {
            std::hint::spin_loop();
            while self.stream.is_none() {
                let stream = TcpStream::connect(String::from("127.0.0.1:") + &PORT.to_string());
                if let Ok(stream) = stream {
                    println!("Connection Successful");
                    self.stream = Some(stream);
                } else if let Err(e) = stream {
                    println!("Connection failed: {}", e);
                }
            }
            if !flag {
                let entry = self.get_entry().unwrap();
                let _ = self.entry_viewer.send(Some(entry));
                flag = true;
            }
            let _ = self.ui.render_to_screen(&mut self.screen);
            let (seq_num, changes) = self.screen.get_changes(self.seq_num);
            self.seq_num = seq_num;
            let _ = self.term.render(&changes);
        }
    }

    fn get_entry(&mut self) -> Result<Entry, DataError> {
        if let Some(stream) = &mut self.stream {
            let request = BoardRequest::GetEntry { user_id: self.user_id, entry_id: 0 }.into_data();
            let _ = stream.write_all(&(request.len() as u64).to_le_bytes());
            let _ = stream.write_all(&request);
            let mut num_bytes = [0; 8];
            let _ = stream.read_exact(&mut num_bytes);
            let num_bytes = u64::from_le_bytes(num_bytes) as usize;
            println!("num_bytes: {}", num_bytes);
            let mut buffer = vec![0; num_bytes];
            let _ = stream.read_exact(&mut buffer);
            let BoardResponse::GetEntry(entry) = BoardResponse::from_data(&buffer)? else {return Err(DataError::InternalError)};
            Ok(entry)
        } else {
            Err(DataError::InternalError)
        }

    }
}

fn main() {
    let mut client = Client::new().unwrap();
    client.mainloop();

    
}