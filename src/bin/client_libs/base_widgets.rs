use crossterm::event::Event;
use ratatui::style::{Style, Stylize};
use ratatui::{
    text::{Line, Text},
    widgets::{Block, Paragraph, Widget},
    layout::Rect,
    buffer::Buffer,
};
use super::utils::*;
use crate::*;

#[derive(Debug)]
pub struct ScrollContainer<T> {
    pub cursor_pos: Option<usize>,
    pub items: Vec<T>,
}

impl<T> ScrollContainer<T> {
    pub fn new(items: Vec<T>) -> Self {
        Self {
            cursor_pos: None,
            items
        }
    }

    pub fn push(&mut self, item: T) {
        self.items.push(item);
    }

    pub fn remove(&mut self) -> T {
        if let Some(cursor_pos) = &mut self.cursor_pos {
            let out = self.items.remove(*cursor_pos);
            *cursor_pos -= 1;
            out
        } else {
            panic!("Can't remove from an unselected ScrollContainer")
        }
    }

    pub fn replace_items(&mut self, items: Vec<T>) {
        self.items = items;
        if let Some(cursor_pos) = self.cursor_pos {
            self.cursor_pos = Some(cursor_pos.min(self.items.len()));
        }
    }

    pub fn selection(&self) -> Option<(usize, &T)> {
        if let Some(cursor_pos) = self.cursor_pos {
            Some((cursor_pos, &self.items[cursor_pos]))
        } else {
            None
        }
    }

    // same as selection but it consumes the items (must be reset using `replace_items`) to return an owned item
    pub fn consume_selection(&mut self) -> Option<(usize, T)> {
        if let Some(cursor_pos) = self.cursor_pos {
            self.items.truncate(cursor_pos + 1);
            let item = self.items.pop().unwrap();
            self.items.clear(); // for keeping the items consistent but not strictly necessary
            Some((cursor_pos, item))
        } else {
            None
        }
    }

    pub fn base_render<'a, U: Into<Line<'a>>, F: Fn(&T) -> String>(&self, area: Rect, buf: &mut Buffer, title: U, f: F) -> Rect {
        let mut block = Block::bordered()
            .title(title);

        if let Some(_) = self.cursor_pos { // ie. is focused
            block = block.border_style(Style::new().bold());
        }
        
        let mut text = Text::default();
        for (idx, item) in self.items.iter().enumerate() {
            let mut line = Line::from((f)(item));
            if self.cursor_pos.map_or(false, |cursor_pos| cursor_pos == idx) {
                line = line.bold();
            }
            text.push_line(line);
        }
        
        let sub_area = if let Some(cursor_pos) = self.cursor_pos {
            let block_inner = block.inner(area);
            Rect::new(block_inner.x, block_inner.y - cursor_pos as u16, block_inner.width, 1)
        } else {
            block.inner(area)
        };
        Paragraph::new(text)
            .block(block)
            .render(area, buf);
        sub_area
    }

    pub fn base_handle_event(&mut self, event: Event) -> Option<StateChange> {
        if let Event::Key(key_event) = event {
            if !key_event.is_press() {return None}
            match key_event.code {
                down!() => {
                    if let Some(cursor_pos) = &mut self.cursor_pos {
                        *cursor_pos += 1;
                        *cursor_pos %= self.items.len();
                    } else {
                        self.cursor_pos = Some(0);
                    }
                    return Some(StateChange::Blank);
                }
                up!() => {
                    if let Some(cursor_pos) = &mut self.cursor_pos {
                        *cursor_pos += self.items.len();
                        *cursor_pos -= 1;
                        *cursor_pos %= self.items.len();
                    } else {
                        self.cursor_pos = Some(0);
                    }
                    return Some(StateChange::Blank);
                }
                
                x => {
                    let _ = pass_direction!(x);
                }
            }
        }
        None
    }

    pub fn focus(&mut self) {
        if self.cursor_pos.is_none() {
            self.cursor_pos = Some(0);
        }    
    }

    pub fn unfocus(&mut self) {
        self.cursor_pos = None;
    }
}


#[derive(Debug)]
pub struct TextEntry {
    pub text: Vec<char>,
    cursor_pos: usize,
    max_size: usize,
}

impl TextEntry {
    pub fn new(size: usize) -> Self {
        Self { text: Vec::new(), cursor_pos: 0, max_size: size }
    }
}

impl InputWidget for TextEntry {
    fn render(&self, area: Rect, buf: &mut Buffer) -> Rect {
        let mut line = Line::default();
        line.push_span(self.text[..self.cursor_pos].iter().collect::<String>());
        if self.cursor_pos < self.max_size {
            if self.cursor_pos < self.text.len() {
                line.push_span(self.text[self.cursor_pos].reversed());
                if self.cursor_pos + 1 < self.text.len() {
                    line.push_span(self.text[self.cursor_pos + 1..].iter().collect::<String>());
                }
            } else {
                line.push_span(' '.reversed());
            }
        }
        line.left_aligned()
            .render(area, buf);
        area
    }

    fn handle_event(&mut self, event: Event) -> Option<StateChange> {
        let mut matched = true;
        if let Event::Key(key_event) = event {
            if !event.is_key_press() {return None}
            match key_event.code {
                KeyCode::Backspace => {
                    if self.cursor_pos > 0 {self.cursor_pos -= 1; self.text.remove(self.cursor_pos);}
                }
                KeyCode::Delete => {
                    if self.cursor_pos < self.text.len() {self.text.remove(self.cursor_pos);}
                }
                KeyCode::Enter => {return Some(StateChange::Pop)}
                KeyCode::Char(c) => {
                    if self.text.len() < self.max_size {
                        self.text.insert(self.cursor_pos, c);
                        self.cursor_pos += 1;
                    }
                },
                x => {
                    let _ = pass_direction!(x);
                    matched = false;
                }
            }
        }
        if matched {
            Some(StateChange::Blank)
        } else {
            None
        }
    }

    fn consume_child(&mut self, child: ClientState) -> Option<StateChange> {
        if let ClientState::Blank | ClientState::Error(_) = child {} else {
            eprintln!("unexpected child of EntryVariantSelector")
        }
        None
    }
}
