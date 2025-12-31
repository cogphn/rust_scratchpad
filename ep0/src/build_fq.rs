use std::io::prelude::*;
use std::net::TcpStream;
use ssh2::Session;
use std::env;

struct FileDeet {
    filename: String,
    filesize: i64
}


fn get_files(lsoutput: String) -> Vec<FileDeet> {
    //let mut ret = Vec::new();
    let mut ret: Vec<FileDeet> = Vec::new();
    let filelines = lsoutput.split("\n");
    for fileline in filelines {
        //ret.push(fileline.to_string());
        let mut fl_data = fileline.split(" ");
        //println!("{:?}", fl_data.nth(0));
        let mut fd_entry = FileDeet{ filename: "".to_string(), filesize: 0 };
        
        match fl_data.next() {
            Some(x) => {
                if x == "" {
                    continue;
                } else {
                    
                    fd_entry.filesize = x.parse::<i64>().unwrap_or(0);
                }
            },
            None => continue
        };
        
        match fl_data.next() {
            Some(x) => {
                fd_entry.filename = x.to_string();
            },
            None => continue
        }        
        ret.push(fd_entry);
    }
    //return Vec::new();
    return ret;
}


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
        //let _ = channel.exec("ls -l /media/disk2/evidence/collections | awk '{print $5, $9}'").unwrap();
        let _ = channel.exec("ls -l /media/disk2/backups | awk '{print $5, $9}'").unwrap();
        //let _ = channel.exec("du /media/disk2/evidence/collections/").unwrap();
        let mut resp_str = String::new();
        channel.read_to_string(&mut resp_str).unwrap();
        //
        let filelist = get_files(resp_str.clone());
        for fileitem in filelist {
            println!(" --> {}, {}", fileitem.filename, fileitem.filesize);
        }

        //
        //let str1 = resp_str.split("\n");
        //println!(" [*] Directory listing: \n{}", resp_str);
        
        channel.wait_close().unwrap();
    }
    
    println!("[.] Done!");

    
}