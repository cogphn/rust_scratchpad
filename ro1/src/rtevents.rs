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
use super::snapshot;

pub mod etwevents;

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename = "Win32_Process")] 
#[serde(rename_all = "PascalCase")]
pub struct Process {
    pub process_id: u32,
    pub name: String,
    pub executable_path: Option<String>,
    pub command_line: Option<String>,    
    pub creation_date: Option<String>,    
    pub description : Option<String>,    
    pub handle : Option<String>,
    pub handle_count : Option<u32>,    
    pub parent_process_id : Option<u32>,
    pub os_name : Option<String>,
    pub windows_version : Option<String>,
    pub session_id : Option<u32>
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
    pub creation_date_utc: NaiveDateTime,
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




pub async fn write_proclist_to_cache() -> Result<(), Box<dyn std::error::Error>> {    
    let process_list = match snapshot::get_process_list() {
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

pub async fn write_netconns_to_cache() -> Result<(), Box<dyn std::error::Error>> {
    let netconn_list = match snapshot::get_netconn_list() {
        Ok(nl) => nl,
        Err(e) => {
            return Err(e);
        }
    };

    for nl in netconn_list {
        let er = parser::netconn_to_er(nl);
        if let Ok(er) = er {
            let _ = cache::insert_event(&er).await;
        }
    }
    Ok(())
}

pub async fn write_services_to_cache() -> Result<(), Box<dyn std::error::Error>> {
    let service_list = match snapshot::get_service_list() {
        Ok(sl) => sl,
        Err(e) => {
            return Err(e);
        }
    };

    for sl in service_list {
        let er = parser::service_to_er(sl);
        if let Ok(er) = er {
            let _ = cache::insert_event(&er).await;
        }
    }

    

    Ok(())
}

pub fn process_observer2() -> Result<(), Box<dyn std::error::Error>> {
    println!("[*] Monitoring for new process creation...");
    let com_lib = COMLibrary::new()?;
    let wmi_con = WMIConnection::new(com_lib)?;
    let new_proc_query = "SELECT * FROM Win32_ProcessStartTrace";
    let mut process_start_stream = wmi_con.async_raw_notification(new_proc_query)?;

    let rt = tokio::runtime::Runtime::new()?;

    rt.block_on(async {
        loop{
            tokio::select! {
                newproc = process_start_stream.next() => {
                    match newproc {
                        Some(Ok(process)) => {
                            let _newproc = match parser::proc_hm_to_pi(&process, "Win32_ProcessStartTrace") {
                                Ok(pi) => {
                                    println!("{}",serde_json::to_string(&pi).unwrap());    
                                    let parsed_procinfo = parser::pi_to_er(&pi, "PROC");
                                    if let Ok(er) = parsed_procinfo {
                                        let _ = cache::insert_event(&er).await.ok();
                                    }
                                },
                                Err(e) => {
                                    eprintln!(" [!] Error parsing process details: {:?}", e);                                
                                }
                            };
                        },
                        Some(Err(_e)) => {},
                        None => {}
                    };
                }
                _ = tokio::signal::ctrl_c() => {
                    println!("   [DBG] ctrl+c receivled - shutting down process obsever");
                    break;
                }
            }
        }
    });
    
    println!("[DBG - rtevents::process_observer2] - returning");
    Ok(())
}


pub async fn process_observer(running: Arc<AtomicBool>) -> Result<(), Box<dyn std::error::Error>> {
    println!("[*] Monitoring for new process creation...\n");
    let com_lib = COMLibrary::new()?;
    let wmi_con = WMIConnection::new(com_lib)?;
    let new_proc_query = "SELECT * FROM Win32_ProcessStartTrace";

    // NOTE: Replace with the correct async notification method for your wmi crate version
    let mut process_start_stream = wmi_con.async_raw_notification(new_proc_query)?;


    while running.load(Ordering::SeqCst) == true {
    //loop {
    //    if running.load(Ordering::SeqCst) == false { // TODO: Fix shutdown delay - seems to only register after another proc event is captured 
    //        println!("[*] Stopping process observer ...");
    //        break;
    //    }
        match process_start_stream.next().await { //TODO: fix this
            Some(event) => {
                match event {
                    Ok(process) => {                        
                        let _newproc = match parser::proc_hm_to_pi(&process, "Win32_ProcessStartTrace") {
                            Ok(pi) => {
                                println!("{}",serde_json::to_string(&pi).unwrap());    
                                let parsed_procinfo = parser::pi_to_er(&pi, "PROC");
                                
                                if let Ok(er) = parsed_procinfo {
                                    let _ = cache::insert_event(&er).await.ok();
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



pub fn get_process_by_id(process_id: u32) -> Process {    
    let defaultproc = Process {
        process_id: 0,
        name: "*NA".to_string(),
        executable_path: Some("*NA".to_string()),
        command_line: Some("*NA".to_string()),    
        creation_date: Some("*NA".to_string()),    
        description : Some("*NA".to_string()),    
        handle : Some("*NA".to_string()),
        handle_count: Some(0),
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
                        Description, ExecutionState, Handle, HandleCount, InstallDate, OSName, WindowsVersion, SessionId
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

    let _ = match etwevents::stop_dns_event_observer(trace) {
        Ok(_) => {
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

    let _ = match etwevents::stop_etw_providers(trace) {
        Ok(_) => {
            println!("[*] Trace stopped successfully");
            return;
        }
        Err (traceerr) => {
            eprintln!("[!] Error stopping trace: {:?}", traceerr);
            return;
        }
    };
}
