use serde::Deserialize;
//use windows::Win32::System::Wmi::MI_Datetime;
use wmi::{COMLibrary, WMIConnection, Variant};

use std::collections::HashMap;
//use std::time::Duration;
use futures::StreamExt;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};


#[derive(Deserialize, Debug)]
#[serde(rename = "Win32_Process")] 
#[serde(rename_all = "PascalCase")]
struct Process {
    process_id: u32,
    name: String,
    executable_path: Option<String>,
    command_line: Option<String>,
    parent_process_id: u32,
    //creation_date
    //creation_date: Option<String>
    // TODO: look into other attribs 
}

/*
#[derive(Deserialize, Debug)]
#[serde(rename = "__InstanceCreationEvent")]
#[serde(rename_all = "PascalCase")]
struct NewProcessEvent {
    target_instance: Process
}
 */

pub static mut RUNNING: AtomicBool = AtomicBool::new(true);


pub fn get_process_list() -> wmi::WMIResult<()> {
    let com_lib = COMLibrary::new()?;
    let wmi_con = WMIConnection::new(com_lib)?;
    

    let processes: Vec<Process> = wmi_con.query()?;

    for process in processes {
        println!("Process ID: {}, Parent Process ID: {} Name: {}, Path: {:?}, Command Line:{:?}",
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
    println!("\nMonitoring for new process creation...\n");
    let com_lib = COMLibrary::new()?;
    let wmi_con = WMIConnection::new(com_lib)?;
    let new_proc_query = "SELECT * FROM Win32_ProcessStartTrace";

    // NOTE: Replace with the correct async notification method for your wmi crate version
    let mut process_start_stream = wmi_con.async_raw_notification(new_proc_query)?;
    /*
    while let Some(event) = process_start_stream.next().await {
        match event {
            Ok(process) => {
                println!("New process started:");
                print_process_info(&process, "Win32_ProcessStartTrace");
            }
            Err(e) => eprintln!("Error receiving event: {:?}", e),
        }
    }
    */

    loop {
        if running.load(Ordering::SeqCst) == false {
            println!("[*] Stopping process observer ...");
            break;
        }
        match process_start_stream.next().await {
            Some(event) => {
                match event {
                    Ok(process) => {
                        println!("New process started:");
                        print_process_info(&process, "Win32_ProcessStartTrace");
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
    

    let mut name: String = "N/A".to_string();
    let mut cmd_line = "N/A".to_string();
    let mut parent_pid: String = "N/A".to_string();
    let mut pid :String = "N/A".to_string();

    if classname == "Win32_Process" {
        name = match process.get("Name") {
            Some(Variant::String(s)) => s.to_string(),
            _ => "Unknown".to_string(),
        };

        cmd_line = match process.get("CommandLine") {
            Some(Variant::String(s)) => s.to_string(),
            Some(Variant::Null) => "None".to_string(),
            _ => "Unknown".to_string(),
        };
        parent_pid = match process.get("ParentProcessId") {
            Some(Variant::UI4(id)) => id.to_string(),
            Some(Variant::Null) => "None".to_string(),
            _ => "Unknown".to_string(),
        };
        pid = match process.get("ProcessId") {
            Some(Variant::UI4(id)) => id.to_string(),
            Some(Variant::String(s)) => s.to_string(), // Win32_ProcessStartTrace returns PID as String
            _ => "Unknown".to_string(),
        };
    } else if classname == "Win32_ProcessStartTrace" {
       
        name = match process.get("ProcessName") {
            Some(Variant::String(s)) => s.to_string(),
            _ => "Unknown".to_string(),
        };

        parent_pid = match process.get("ParentProcessID") {
            Some(Variant::UI4(id)) => id.to_string(),
            Some(Variant::Null) => "None".to_string(),
            _ => "Unknown".to_string(),
        };
        pid = match process.get("ProcessID") {
            Some(Variant::UI4(id)) => id.to_string(),
            Some(Variant::String(s)) => s.to_string(), // Win32_ProcessStartTrace returns PID as String
            _ => "Unknown".to_string(),   
        };

        let pid_u32:u32 = match process.get("ProcessID") {
            Some(Variant::UI4(id)) => *id,
            _ => 0,
        };
         
        let process_details = get_process_details(pid_u32);
        
        cmd_line = match process_details{
            Ok(details) => match details.get("CommandLine") {
                Some(Variant::String(s)) => s.to_string(),
                Some(Variant::Null) => "None".to_string(),
                _ => "Unknown".to_string(),
            },
            Err(_) => "N/A".to_string(),
        };

    }
  
    println!("Process: {} (PID: {})", name, pid);
    println!("Command Line: {}", cmd_line);
    println!("Parent PID: {}", parent_pid);
    println!("---");

}


fn get_process_details(process_id: u32) -> Result<HashMap<String, Variant>, Box<dyn std::error::Error>> {
    let com_con = COMLibrary::new()?;
    let wmi_con = WMIConnection::new(com_con)?;

    let query = format!("SELECT Name, ProcessId, CommandLine, ParentProcessId FROM Win32_Process WHERE ProcessId = {}", process_id);
    let results: Vec<HashMap<String, Variant>> = wmi_con.raw_query(&query)?;

    if let Some(process) = results.into_iter().next() {
        Ok(process)
    } else {
        Err("Process not found".into())
    }
}
