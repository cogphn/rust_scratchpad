extern crate argparse;

use local_ip_address::local_ip;
use gethostname::gethostname;
use serde_derive::Deserialize;
use serde_derive::Serialize;
use argparse::{ArgumentParser, Store};

use reqwest::Response;

struct NetInfo {
    ip: String,
    hostname: String
}

#[derive(Debug, Serialize, Deserialize)]
struct PushOverMessage {
    user: String,
    token: String,
    title: String,
    message: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct Config {
    pushovertoken: String,
    pushoveruser: String
}

async fn send_message(msg: &PushOverMessage) -> Response {
    let url: &str = &("https://api.pushover.net/1/messages.json?user=".to_owned() + &msg.user + "&token=" + &msg.token 
    + "&title=" + &msg.title 
    + "&message=" + &msg.message);
    let resp = reqwest::Client::new()
        .post(url)
        .send()
        .await;  
    return resp.expect("ERROR");
}


#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("[*] Starting...");
    let mut configpath = "".to_string();
    {
        let mut ap = ArgumentParser::new();
        ap.refer(&mut configpath).add_option(
            &["-c","--config"],
            Store,
            "table config file"
        ).required();
        ap.parse_args_or_exit();
    }
    

    //let configpath = "whereami.conf";
    let configjsonstring = match std::fs::read_to_string(configpath) { 
        Ok(x) => x.to_string(),
        Err(e) => panic!("[!] cannot read config file: {}",e)
    };
    let configdata : Config = serde_json::from_str(&configjsonstring).expect("error loading config data");


    // get deets 
    let ip = local_ip().unwrap().to_string();
    let hostname = gethostname().into_string().unwrap();
    let ni = NetInfo{ip: ip, hostname:hostname.clone()};
    println!("    {:?}, {:?}", ni.ip, ni.hostname);
    
    let msg = PushOverMessage {
        user: configdata.pushoveruser.to_string(),
        token: configdata.pushovertoken.to_string(),
        title: ni.hostname.to_string(),
        message: format!("Hostname: {}, IP: {}", ni.hostname, ni.ip)
    };
    send_message(&msg).await;
    println!("[.] Done");
    Ok(())

}

//