
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

~~~


## main.rs
~~~rust
use chrono::{DateTime, Utc, NaiveDateTime, ParseError, Local }; //, ParseError};
use wmi::{COMLibrary, WMIConnection, Variant};
use std::collections::HashMap;
use serde::Deserialize;

use netstat_esr::{get_sockets_info, AddressFamilyFlags, ProtocolFlags, ProtocolSocketInfo};



use std::error::Error;


#[derive(Debug)]
pub struct ProcessInfo {
    pub process_id: u32,
    pub creation_date: NaiveDateTime,
    pub creation_date_utc: NaiveDateTime,
    pub command_line: String,
    pub name: String,
    pub executable_path: String,
    pub parent_process_id: u32,
    pub description: String,
    pub handle: String,
    pub handle_count: u32,
    pub os_name: String,
    pub windows_version: String,
    pub session_id: u32,
}

#[derive(Deserialize, Debug)]
#[serde(rename = "Win32_Process")]
#[serde(rename_all = "PascalCase")]
struct Process {
    process_id: u32,
    name: String,
    executable_path: Option<String>,
    command_line: Option<String>,    
    //creation_class_name: String,
    //caption: Option<String>,    
    creation_date: Option<String>,    
    //cs_creation_class_name : Option<String>,    
    //cs_name : Option<String>,
    description : Option<String>,    
    //execution_state : Option<u16>,
    handle : Option<String>,
    handle_count : Option<u32>,    
    parent_process_id : Option<u32>,
    os_name : Option<String>,
    windows_version : Option<String>,
    session_id : Option<u32>
}


struct Netconn {
    process_name: String,
    local_address: String,
    remote_address: String
}



fn main() {
    println!("[*] starting...");

    let localtime = Local::now();
    let tzoffset = localtime.offset();
    let dtnow: NaiveDateTime = localtime.naive_local();

    let af_flags = AddressFamilyFlags::IPV4 | AddressFamilyFlags::IPV6;
    let proto_flags = ProtocolFlags::TCP | ProtocolFlags::UDP;
    let sockets_info = get_sockets_info(af_flags, proto_flags).unwrap();

      
    for si in sockets_info {
        

        
        let x = si.associated_pids.clone();
        x.into_iter().for_each(|pid|{
            let z = get_process_details(pid as u32);
            println!("{:?}", z);
            
        });

        match si.protocol_socket_info {
            ProtocolSocketInfo::Udp(usi) => {
                println!("UDP!: Local Addr: {},     Local Port: {}  Remote Addr: {} Remote port: {} associated_pids: {:?}", 
                    usi.local_addr, usi.local_port, usi.remote_addr, usi.remote_port, si.associated_pids
                );
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


pub fn get_process_list() -> Result<Vec<ProcessInfo>, Box<dyn std::error::Error>> {
    let com_lib = COMLibrary::new()?;
    let wmi_conn = WMIConnection::new(com_lib)?;
    
    let processes: Vec<Process> = wmi_conn.query()?;
    let process_infos: Vec<ProcessInfo> = processes
        .into_iter()
        .map(|p| { 
            let cd = p.creation_date.unwrap_or("1970-01-01T00:00:00".to_string());

            ProcessInfo { 
                process_id: p.process_id as u32,
                creation_date: convert_wmi_datetime_to_datetime(&cd).expect("1970-01-01T00:00:00"),
                creation_date_utc: convert_wmi_datetime_to_datetime_utc(&cd).expect("1970-01-01T00:00:00"),
                command_line: p.command_line.unwrap_or("*NA".to_string()),
                name: p.name,
                description: p.description.unwrap_or("*NA".to_string()),
                executable_path: p.executable_path.unwrap_or("*NA".to_string()),
                handle: p.handle.unwrap_or("*NA".to_string()),
                handle_count: p.handle_count.unwrap_or(0),
                parent_process_id: p.parent_process_id.unwrap_or(0),
                os_name: p.os_name.unwrap_or("*NA".to_string()),
                session_id: p.session_id.unwrap_or(0),
                windows_version: p.windows_version.unwrap_or("*NA".to_string())

            }
        }).collect();
    
    return Ok(process_infos);
}



pub fn get_process_details(process_id: u32) -> Result<HashMap<String, Variant>, Box<dyn std::error::Error>> {
    let com_con = COMLibrary::new()?;
    let wmi_con = WMIConnection::new(com_con)?;

    let query = format!(r#"SELECT CreationDate, Name, ProcessId, CommandLine, ParentProcessId, ExecutablePath, 
                        Description, ExecutionState, Handle, InstallDate, OSName, WindowsVersion, SessionId
                         FROM Win32_Process WHERE ProcessId = {}"#
                         , process_id);
    let results: Vec<HashMap<String, Variant>> = wmi_con.raw_query(&query)?;
    if let Some(process) = results.into_iter().next() {
        Ok(process)
    } else {
        Err("Process not found".into())
    }
    
}

~~~
