use message_board::*;
use std::io::Write;
use std::net::*;

fn main() {
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