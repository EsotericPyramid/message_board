use message_board::*;
use termwiz::terminal::Terminal;
use std::io::Write;
use std::net::*;
use std::rc::Rc;
use termwiz::surface::{Surface, Change, Position, SequenceNo};
use termwiz::widgets::Widget;

/// just views an entry's content (not the header)
struct EntryViewer {
    entry: Option<Rc<Entry>>,
}

impl EntryViewer {
    fn new() -> Self {
        Self { entry: None }
    }
}

impl Widget for EntryViewer {
    fn render(&mut self, args: &mut termwiz::widgets::RenderArgs) {
        if let None = self.entry {
            args.surface.add_changes(vec![Change::Text("No selected entry to display :P".to_string()), Change::CursorPosition { x: Position::Absolute(0), y: Position::Absolute(0) }]);
        }
    }
}

struct Client<'a> {
    term: Box<dyn Terminal>,
    screen: Surface,
    seq_num: SequenceNo,
    ui: termwiz::widgets::Ui<'a>,
    root_widget: termwiz::widgets::WidgetId,
}

impl<'a> Client<'a> {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let term_caps = termwiz::caps::Capabilities::new_from_env()?;
        let mut term = termwiz::terminal::new_terminal(term_caps)?;
        let size = term.get_screen_size()?;
        let screen = Surface::new(size.cols, size.rows);

        let mut ui = termwiz::widgets::Ui::new();
        let root_widget = ui.set_root(EntryViewer::new());
        Ok(Self { 
            term: Box::new(term),
            screen,
            seq_num: 0,
            ui,
            root_widget,
        })
    }

    fn mainloop(&mut self) {
        loop {
            std::hint::spin_loop();
            let _ = self.ui.render_to_screen(&mut self.screen);
            let (seq_num, changes) = self.screen.get_changes(self.seq_num);
            self.seq_num = seq_num;
            let _ = self.term.render(&changes);
        }
    }
}

fn main() {
    let mut client = Client::new().unwrap();
    client.mainloop();

    let stream = TcpStream::connect(String::from("127.0.0.1:") + &PORT.to_string());
    if let Ok(mut stream) = stream {
        println!("Connection Successful");

        let _ = stream.write("TEST TEST 123!!".as_bytes());

        

        println!("Dropping Connection");
        drop(stream);
    } else if let Err(e) = stream {
        println!("Connection failed: {}", e);
    }
}