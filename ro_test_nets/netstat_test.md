
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

use netstat_esr::{AddressFamilyFlags, ProtocolFlags};
use std::collections::HashMap;
use wmi::WMIConnection;
use wmi::COMLibrary;
use wmi::Variant;
use serde::Deserialize;


#[derive(Deserialize, Debug)]
#[serde(rename = "Win32_Process")] 
#[serde(rename_all = "PascalCase")]
pub struct Process {
    pub process_id: u32,
    pub name: String,
    pub executable_path: Option<String>,
    pub command_line: Option<String>,    
    //pub creation_class_name: String,
    //pub caption: Option<String>,    
    pub creation_date: Option<String>,    
    //pub cs_creation_class_name : Option<String>,    
    //pub cs_name : Option<String>,
    pub description : Option<String>,    
    //pub execution_state : Option<u16>,
    pub handle : Option<String>,
    pub handle_count : Option<u32>,    
    pub parent_process_id : Option<u32>,
    pub os_name : Option<String>,
    pub windows_version : Option<String>,
    pub session_id : Option<u32>
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



fn main() {
    let af_flags = AddressFamilyFlags::IPV4 | AddressFamilyFlags::IPV6;
    let proto_flags = ProtocolFlags::TCP | ProtocolFlags::UDP;
    let sockets_info = netstat_esr::get_sockets_info(af_flags, proto_flags).unwrap();
    for si in sockets_info {
        println!("Active connection: {}",si);
        println!("Associated PIDs: {:?}", si.associated_pids);
    }
}



~~~
