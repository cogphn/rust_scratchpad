
## Cargo.toml
~~~toml
[package]
name = "nettest1"
version = "0.1.0"
edition = "2024"

[dependencies]
netstat-esr = "0.8.1"
wmi = "0.17.2"
serde = { version = "1.0", features = ["derive"] }
chrono = "0.4.42"

~~~


## main.rs
~~~rust
use chrono::{DateTime, Utc, NaiveDateTime, ParseError, Local }; //, ParseError};
use wmi::{COMLibrary, WMIConnection, Variant};
use std::collections::HashMap;
use serde::Deserialize;

use netstat_esr::{get_sockets_info, AddressFamilyFlags, ProtocolFlags, ProtocolSocketInfo};



#[derive(Deserialize, Debug)]
#[serde(rename = "Win32_Process")]
#[serde(rename_all = "PascalCase")]
struct Process {
    process_id: u32,
    name: String,
    executable_path: Option<String>,
    command_line: Option<String>,    
    creation_date: Option<String>,    
    description : Option<String>,    
    handle : Option<String>,
    //handle_count : Option<u32>, //troublesome:  Err(HResultError { hres: -2147217406 }) [on review - maybe because you did not select it in the query lol ]
    parent_process_id : Option<u32>,
    os_name : Option<String>,
    windows_version : Option<String>,
    session_id : Option<u32>
    
}





fn main() {
    println!("[*] starting...");

    let af_flags = AddressFamilyFlags::IPV4 | AddressFamilyFlags::IPV6;
    let proto_flags = ProtocolFlags::TCP | ProtocolFlags::UDP;
    let sockets_info = get_sockets_info(af_flags, proto_flags).unwrap();

    // tests 
    //let pid: u32 = 3200;
    //let process_data = get_process_by_id(pid);
    //println!("{:?}", process_data);

    for si in sockets_info {

        let x = si.associated_pids.clone();
        
        // DBG
        /*
        x.into_iter().for_each(|pid|{
            let z = get_process_by_id(pid as u32);
            println!("{:?}", z);
        });
        */

        let conn_process_list: Vec<Process> = x.into_iter().map(|pid|{
            get_process_by_id(pid)
        }).collect();
        

        match si.protocol_socket_info {
            ProtocolSocketInfo::Udp(usi) => {
                println!("UDP!: Local Addr: {},     Local Port: {}  Remote Addr: {} Remote port: {} associated_pids: {:?}", 
                    usi.local_addr, usi.local_port, usi.remote_addr, usi.remote_port, si.associated_pids
                );
                println!("{:?}", conn_process_list);
            },
            ProtocolSocketInfo::Tcp(tsi) => {
                println!("TCP!: Local Addr: {},     Local Port: {}  Remote Addr: {} Remote port: {} state: {}, associated_pids: {:?}", 
                    tsi.local_addr, tsi.local_port, tsi.remote_addr, tsi.remote_port, tsi.state, si.associated_pids
                );
            },
        }
      
    }
    
    
    println!("[.] Done.");
}


pub fn convert_wmi_datetime_to_datetime(wmi_date: &str) -> Result<NaiveDateTime, ParseError> { 
    if wmi_date.len() < 14 {
        return NaiveDateTime::parse_from_str("1970-01-01T00:00:00", "%Y-%m-%dT%H:%M:%S");
    }
    let dt_str = &wmi_date[0..14];    
    if let Ok(naive_dt) = NaiveDateTime::parse_from_str(dt_str, "%Y%m%d%H%M%S") {
        return Ok(naive_dt);
    } else {
        return NaiveDateTime::parse_from_str("1970-01-01T00:00:00", "%Y-%m-%dT%H:%M:%S");
    }
}


pub fn convert_wmi_datetime_to_datetime_utc(wmi_date: &str) -> Result<NaiveDateTime, ParseError> { 
    if wmi_date.len() < 14 {
        return NaiveDateTime::parse_from_str("1970-01-01T00:00:00", "%Y-%m-%dT%H:%M:%S");
    }
    
    let dt_str = &wmi_date[0..14];    
    if let Ok(naive_dt) = NaiveDateTime::parse_from_str(dt_str, "%Y%m%d%H%M%S") {
        let dt_utc = naive_dt.and_local_timezone(Local).unwrap();
        return Ok(dt_utc.naive_utc());
    } else {
        return NaiveDateTime::parse_from_str("1970-01-01T00:00:00", "%Y-%m-%dT%H:%M:%S");
    }
}


pub fn get_process_by_id(process_id: u32) -> Process {    
    let defaultproc = Process {
        process_id: 0,
        name: "*NA".to_string(),
        executable_path: Some("*NA".to_string()),
        command_line: Some("*NA".to_string()),    
        creation_date: Some("*NA".to_string()),    
        description : Some("*NA".to_string()),    
        handle : Some("*NA".to_string()),
        parent_process_id : Some(0),
        os_name : Some("*NA".to_string()),
        windows_version : Some("*NA".to_string()),
        session_id : Some(0)
    };

    let com_con = match COMLibrary::new() {
        Ok(v) => v,
        _ => {
            return defaultproc
        }
    };

    
    let wmi_con = match WMIConnection::new(com_con){
        Ok(v) => v,
        _ => {
            return defaultproc
        }
    };

    let query = format!(r#"SELECT CreationDate, Name, ProcessId, CommandLine, ParentProcessId, ExecutablePath, 
                        Description, ExecutionState, Handle, InstallDate, OSName, WindowsVersion, SessionId
                         FROM Win32_Process WHERE ProcessId = {}"#
                         , process_id);
    let results: Vec<Process> = match wmi_con.raw_query(&query) {
        Ok(v) => v,
        _ => {
            return defaultproc
        }
    };

    if let Some(process) = results.into_iter().next() {
        process
    } else {
        defaultproc
    }
    
}


~~~
