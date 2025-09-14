use serde::Deserialize;
use serde::Serialize;
use wmi::{COMLibrary, WMIConnection, Variant};
use std::collections::HashMap;
use futures::StreamExt;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use chrono::{NaiveDateTime};
use std::sync::OnceLock;

use super::parser;
use super::cache;

pub mod etwevents;

#[derive(Deserialize, Debug)]
#[serde(rename = "Win32_Process")] 
#[serde(rename_all = "PascalCase")]
struct Process {
    process_id: u32,
    name: String,
    executable_path: Option<String>,
    command_line: Option<String>,    
    creation_class_name: String,
    caption: Option<String>,    
    creation_date: Option<String>,    
    cs_creation_class_name : Option<String>,    
    cs_name : Option<String>,
    description : Option<String>,    
    execution_state : Option<u16>,
    handle : Option<String>,
    handle_count : Option<u32>,    
    parent_process_id : Option<u32>,
    os_name : Option<String>,
    windows_version : Option<String>,
    session_id : Option<u32>
}

#[derive(Deserialize,Debug)]
#[derive(Serialize)]
pub struct ProcessInfo {
    pub process_id: u32,
    pub hostname: String,
    pub name: String,
    pub executable_path: String,
    pub command_line: String,
    pub parent_process_id: u32,
    pub creation_date: NaiveDateTime,
    pub description: String,
    //pub execution_state: u16,
    pub handle: String,
    //pub install_date: NaiveDateTime,
    pub handle_count: u32,
    pub os_name: String,
    pub windows_version: String,
    pub session_id: u32,
}

pub static HOSTNAME: OnceLock<String> = OnceLock::new();
pub static mut RUNNING: AtomicBool = AtomicBool::new(true);

pub fn get_hostname() -> String {
    if let Some(hostname) = HOSTNAME.get() {
        return hostname.to_string();
    }

    let com_lib = match COMLibrary::new(){
        Ok(v) => v,
        Err(_) => return "Unknown".to_string()
    };
    let wmi_con = match WMIConnection::new(com_lib){
        Ok(v) => v,
        Err(_) => return "Unknown".to_string()
    };    
    let wmi_computersystem: Vec<HashMap<String, Variant>> = match wmi_con.raw_query("SELECT DNSHostName FROM Win32_ComputerSystem"){
        Ok(v) => v,
        Err(_) => return "Unknown".to_string()
    };

    if let Some(info) = wmi_computersystem.into_iter().next() {
        if let Some(Variant::String(hostname)) = info.get("DNSHostName") {
            HOSTNAME.set(hostname.to_string()).ok();
            return hostname.to_string();
        }
    }
    HOSTNAME.set("Unknown".to_string()).ok();
    "Unknown".to_string()
}




/*
pub fn get_process_list() -> wmi::WMIResult<()> {
    let com_lib = COMLibrary::new()?;
    let wmi_con = WMIConnection::new(com_lib)?;
    

    let processes: Vec<Process> = wmi_con.query()?;

    for process in processes {
        println!("Creation Date: {:?}, Process ID: {}, Parent Process ID: {} Name: {}, Path: {:?}, Command Line:{:?}",
            process.creation_date.expect("1970-01-01T00:00:00").to_rfc3339(),            
            process.process_id,
            process.parent_process_id,
            process.name,
            process.executable_path,
            process.command_line            
        );
    }

    Ok(())
}
*/
pub async fn write_proclist_to_cache() -> Result<(), Box<dyn std::error::Error>> {    
    let process_list = get_process_list()?;
    let process_list = match get_process_list() {
        Ok(pl) => pl,
        Err(e) => {
            return Err(e);
        }
    };

    for pi in &process_list {
        let er = parser::pi_to_er(pi, "PROCLIST");
        if let Ok(er) = er {
            let _ = cache::insert_event(&er).await;
        }
    }
    
    Ok(())
}

pub fn get_process_list() -> Result<Vec<ProcessInfo>, Box<dyn std::error::Error>> {
    let com_lib = COMLibrary::new()?;
    let wmi_con = WMIConnection::new(com_lib)?;
    let processes: Vec<Process> = wmi_con.query()?;
    let process_infos: Vec<ProcessInfo> = processes
        .into_iter()
        .map(|p| { 
            ProcessInfo { 
                process_id: p.process_id,
                hostname: get_hostname(),
                name: p.name,
                executable_path: p.executable_path.unwrap_or_default(),
                command_line: p.command_line.unwrap_or_default(),
                parent_process_id: p.parent_process_id.unwrap_or(0 as u32),
                creation_date: parser::convert_wmi_datetime_to_datetime(&p.creation_date.unwrap_or_default()).expect("1970-01-01T00:00:00"),
                description: p.description.unwrap_or_default(),
                handle: p.handle.unwrap_or_default(),
                handle_count: p.handle_count.unwrap_or_default(),
                os_name: p.os_name.unwrap_or_default(),
                windows_version: p.windows_version.unwrap_or_default(), 
                session_id: p.session_id.unwrap_or_default()
            }
        }).collect();
    
    return Ok(process_infos);
}

pub async fn process_observer(running: Arc<AtomicBool>) -> Result<(), Box<dyn std::error::Error>> {
    println!(" [*] Monitoring for new process creation...\n");
    let com_lib = COMLibrary::new()?;
    let wmi_con = WMIConnection::new(com_lib)?;
    let new_proc_query = "SELECT * FROM Win32_ProcessStartTrace";

    // NOTE: Replace with the correct async notification method for your wmi crate version
    let mut process_start_stream = wmi_con.async_raw_notification(new_proc_query)?;

    loop {
        if running.load(Ordering::SeqCst) == false { // TODO: Fix shutdown delay - seems to only register after another proc event is captured 
            println!("[*] Stopping process observer ...");
            break;
        }
        match process_start_stream.next().await {
            Some(event) => {
                match event {
                    Ok(process) => {                        
                        //print_process_info(&process, "Win32_ProcessStartTrace");
                        let _newproc = match parser::proc_hm_to_pi(&process, "Win32_ProcessStartTrace") {
                            Ok(pi) => {
                                println!("{}",serde_json::to_string(&pi).unwrap());    
                                let parsed_procinfo = parser::pi_to_er(&pi, "PROC");
                                if let Ok(er) = parsed_procinfo {
                                    let _ = cache::get_runtime().spawn(async move {
                                        cache::insert_event(&er).await.ok();
                                    });
                                }
                            },
                            Err(e) => {
                                eprintln!(" [!] Error parsing process details: {:?}", e);                                
                            }
                        };
                    }
                    Err(e) => eprintln!("Error receiving event: {:?}", e),
                }
            }
            None => {
                break;
            }
        }
    }
    Ok(())
}

fn print_process_info(process: &HashMap<String, Variant>, classname: &str) {    
    let newproc = match parser::proc_hm_to_pi(process, classname) {
        Ok(p) => p,
        Err(e) => {
            eprintln!(" [!] Error parsing process details: {:?}", e);
            return;
        }
    };
    println!("{}",serde_json::to_string(&newproc).unwrap());    

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


fn start_netevent_observer() -> Result<ferrisetw::UserTrace, ferrisetw::trace::TraceError> {
    return etwevents::start_tcp_event_observer();
}

fn stop_netevent_observer(trace: ferrisetw::UserTrace) -> Result<(), ferrisetw::trace::TraceError> {
    return etwevents::stop_tcp_event_observer(trace);
}

pub fn netevent_observer(running: Arc<AtomicBool>) {
    let trace_ret = etwevents::start_tcp_event_observer();

    if let Err(e) = &trace_ret {
        eprintln!("[!] Error starting TCPIP trace: {:?}", e);
        return;
    }
    let trace = trace_ret.unwrap();

    while running.load(Ordering::SeqCst) == true {
        std::thread::sleep(std::time::Duration::new(5, 0));
    } 

    let ret = match etwevents::stop_tcp_event_observer(trace) {
        Ok(v) => {
            println!("[*] Trace stopped successfully");
            return;
        }
        Err (traceerr) => {
            eprintln!("[!] Error stopping trace: {:?}", traceerr);
            return;
        }
    };

}

/*
fn start_dns_observer() -> Result<ferrisetw::UserTrace, ferrisetw::trace::TraceError> {
    return etwevents::start_dns_event_observer();
}

fn stop_dns_observer(trace: ferrisetw::UserTrace) -> Result<(), ferrisetw::trace::TraceError> {
    return etwevents::stop_dns_event_observer(trace);
}
    */

pub fn dns_event_observer(running: Arc<AtomicBool>) {
    let trace_ret = etwevents::start_dns_event_observer();

    if let Err(e) = &trace_ret {
        eprintln!("[!] Error starting DNS trace: {:?}", e);
        return;
    }
    let trace = trace_ret.unwrap();

    while running.load(Ordering::SeqCst) == true {
        std::thread::sleep(std::time::Duration::new(5, 0));
    } 

    let ret = match etwevents::stop_dns_event_observer(trace) {
        Ok(v) => {
            println!("[*] Trace stopped successfully");
            return;
        }
        Err (traceerr) => {
            eprintln!("[!] Error stopping trace: {:?}", traceerr);
            return;
        }
    };   
}


pub fn etw_observer(running: Arc<AtomicBool>) {
    //start_etw_providers

    let trace_ret = etwevents::start_etw_providers();

    if let Err(e) = &trace_ret {
        eprintln!("[!] Error starting trace: {:?}", e);
        return;
    }
    let trace = trace_ret.unwrap();

    while running.load(Ordering::SeqCst) == true {
        std::thread::sleep(std::time::Duration::new(5, 0));
    } 

    let ret = match etwevents::stop_etw_providers(trace) {
        Ok(v) => {
            println!("[*] Trace stopped successfully");
            return;
        }
        Err (traceerr) => {
            eprintln!("[!] Error stopping trace: {:?}", traceerr);
            return;
        }
    };
}
