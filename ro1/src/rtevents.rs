use serde::Deserialize;
use serde::Serialize;
//use windows::Win32::System::Wmi::MI_Datetime;
use wmi::{COMLibrary, WMIConnection, Variant};

use std::collections::HashMap;
//use std::time::Duration;
use futures::StreamExt;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use chrono::{DateTime, NaiveDateTime, Utc};
use std::sync::OnceLock;

use super::parser;
use super::cache;

#[derive(Deserialize, Debug)]
#[serde(rename = "Win32_Process")] 
#[serde(rename_all = "PascalCase")]
struct Process {
    process_id: u32,
    name: String,
    executable_path: Option<String>,
    command_line: Option<String>,
    parent_process_id: u32,
    creation_date: Option<DateTime<Utc>>
    //creation_date: Option<String>
    // TODO: look into other attribs 
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
    pub creation_date: NaiveDateTime
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

/*
pub fn get_process_listv2() -> Result<(), std::error::Error> {

    let com_con = COMLibrary::new()?;
    let wmi_con = WMIConnection::new(com_con);
    let initial_processes: Vec<HashMap<String, Variant>> = wmi_con.raw_query("SELECT Name, ProcesId, CommandLine FROM Win32_Process")?;
    return initial_processes;

}
*/




pub async fn process_observer(running: Arc<AtomicBool>) -> Result<(), Box<dyn std::error::Error>> {
    println!(" [*] Monitoring for new process creation...\n");
    let com_lib = COMLibrary::new()?;
    let wmi_con = WMIConnection::new(com_lib)?;
    let new_proc_query = "SELECT * FROM Win32_ProcessStartTrace";

    // NOTE: Replace with the correct async notification method for your wmi crate version
    let mut process_start_stream = wmi_con.async_raw_notification(new_proc_query)?;

    loop {
        if running.load(Ordering::SeqCst) == false { // TODO: Fix shutdown delay
            println!("[*] Stopping process observer ...");
            break;
        }
        match process_start_stream.next().await {
            Some(event) => {
                match event {
                    Ok(process) => {                        
                        //print_process_info(&process, "Win32_ProcessStartTrace");
                        let newproc = match parser::proc_hm_to_pi(&process, "Win32_ProcessStartTrace") {
                            Ok(pi) => {
                                println!("{}",serde_json::to_string(&pi).unwrap());    
                                let parsed_procinfo = parser::pi_to_er(&pi);
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
    /*
    let hostname = get_hostname();
    let mut newproc: ProcessInfo = ProcessInfo { 
        name: "N/A".to_string(),
        hostname: hostname,
        command_line: "N/A".to_string(),
        parent_process_id: 0,
        process_id: 0,
        creation_date: NaiveDateTime::parse_from_str("1970-01-01T00:00:00", "%Y-%m-%dT%H:%M:%S").unwrap(),
        executable_path:"N/A".to_string()
    };
    
    if classname == "Win32_Process" {
        newproc.name = match process.get("Name") {
            Some(Variant::String(s)) => s.to_string(),
            _ => "Unknown".to_string(),
        };

        newproc.command_line = match process.get("CommandLine") {
            Some(Variant::String(s)) => s.to_string(),
            Some(Variant::Null) => "None".to_string(),
            _ => "Unknown".to_string(),
        };
        newproc.parent_process_id = match process.get("ParentProcessId") {
            Some(Variant::UI4(id)) => *id,
            Some(Variant::Null) => 0,   //TODO: fix
            _ => 0,
        };
        newproc.process_id = match process.get("ProcessId") {
            Some(Variant::UI4(id)) => *id,
            Some(Variant::String(_s)) => 0,  //TODO: fix
            _ => 0,
        };
        newproc.creation_date = match process.get("CreationDate") {
            Some(Variant::String(s)) => convert_wmi_datetime_to_datetime(s).unwrap(),            
            _ => NaiveDateTime::parse_from_str("1970-01-01T00:00:00", "%Y-%m-%dT%H:%M:%S").unwrap(),
        };
    } else if classname == "Win32_ProcessStartTrace" {
       
        newproc.name = match process.get("ProcessName") {
            Some(Variant::String(s)) => s.to_string(),
            _ => "Unknown".to_string(),
        };

        newproc.parent_process_id = match process.get("ParentProcessID") {
            Some(Variant::UI4(id)) => *id,
            Some(Variant::Null) => 0,
            _ => 0
        };
        newproc.process_id = match process.get("ProcessID") {
            Some(Variant::UI4(id)) => *id,
            Some(Variant::String(_s)) => 0, 
            _ => 0
        };


         
        let process_details = get_process_details(newproc.process_id);
        
        newproc.command_line = match &process_details{ //TODO: fix 
            Ok(details) => match details.get("CommandLine") {
                Some(Variant::String(s)) => s.to_string(),
                Some(Variant::Null) => "None".to_string(),
                _ => "Unknown".to_string(),
            },            
            Err(_) => "N/A".to_string(),
        };

        newproc.creation_date = match &process_details{
            Ok(procdetails) => match procdetails.get("CreationDate") {
                Some(Variant::String(s)) => {
                    convert_wmi_datetime_to_datetime(s).unwrap()
                },                
                _ => NaiveDateTime::parse_from_str("1970-01-01T00:00:00", "%Y-%m-%dT%H:%M:%S").unwrap(),
            },
            Err(_) => NaiveDateTime::parse_from_str("1970-01-01T00:00:00", "%Y-%m-%dT%H:%M:%S").unwrap(),
        };


    }

    let parsed_procinfo = parser::procdetails_to_er(&newproc);
    let _ = cache::get_runtime().spawn(async move {
        if let Ok(er) = parsed_procinfo {
            cache::insert_event(&er).await.ok();
        }
    });

    println!("{}",serde_json::to_string(&newproc).unwrap());    
    */
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

    let query = format!("SELECT CreationDate, Name, ProcessId, CommandLine, ParentProcessId FROM Win32_Process WHERE ProcessId = {}", process_id);
    let results: Vec<HashMap<String, Variant>> = wmi_con.raw_query(&query)?;

    if let Some(process) = results.into_iter().next() {
        Ok(process)
    } else {
        Err("Process not found".into())
    }
}
