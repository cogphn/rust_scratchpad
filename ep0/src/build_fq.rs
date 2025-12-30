use std::io::prelude::*;
use std::net::TcpStream;
use ssh2::Session;
use std::env;

fn main() {


    let sshpwd: String = match env::var("SSHPWD") {
        Ok(p) => p,
        Err(_e) => {
            println!("    [!] password not specified - trying a blank password");
            "".to_string()
        }
    };

    let tcp = TcpStream::connect("dev01:22").unwrap();
    let mut sess = Session::new().unwrap();
    sess.set_tcp_stream(tcp);
    sess.handshake().unwrap();
    sess.userauth_password("examiner", &sshpwd).unwrap();

    if sess.authenticated() {
        println!("[DBG] authenticated!");
        let mut channel = sess.channel_session().unwrap();
        let _ = channel.exec("ls /media/disk2/evidence/collections").unwrap();
        let mut resp_str = String::new();
        channel.read_to_string(&mut resp_str).unwrap();
        println!(" [*] Directory listing: \n{}", resp_str);
        channel.wait_close().unwrap();
    }
    
    println!("[.] Done!");

    
}