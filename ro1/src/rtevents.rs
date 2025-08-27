use serde::Deserialize;
use serde::Serialize;
//use windows::Win32::System::Wmi::MI_Datetime;
use wmi::{COMLibrary, WMIConnection, Variant};

use std::collections::HashMap;
//use std::time::Duration;
use futures::StreamExt;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use chrono::{DateTime, NaiveDateTime, ParseError, Utc};


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
struct ProcessInfo {
    process_id: u32,
    name: String,
    executable_path: String,
    command_line: String,
    parent_process_id: u32,
    creation_date: NaiveDateTime
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
    println!("\nMonitoring for new process creation...\n");
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
                        //println!("New process started:");
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
    

    let mut newproc: ProcessInfo = ProcessInfo { 
        name: "N/A".to_string(),
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
            Some(Variant::String(s)) => 0,  //TODO: fix
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
            Some(Variant::String(s)) => 0, 
            _ => 0
        };

        let pid_u32:u32 = match process.get("ProcessID") {
            Some(Variant::UI4(id)) => *id,
            _ => 0,
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

    println!("{}",serde_json::to_string(&newproc).unwrap());    

}


fn convert_wmi_datetime(wmi_date: &str) -> String { //TODO: fix timezone issue 
    if wmi_date.len() < 14 {
        return "1970-01-01T00:00:00".to_string().into();
    }
    let dt_str = &wmi_date[0..14];    
    if let Ok(naive_dt) = NaiveDateTime::parse_from_str(dt_str, "%Y%m%d%H%M%S") {
        //Some(DateTime::from_utc(naive_dt, Utc))
        let datetime: DateTime<Utc> = DateTime::from_utc(naive_dt, Utc);
        return datetime.to_rfc3339().into();
    } else {
        return "1970-01-01T00:00:00".to_string().into();
    }
}


fn convert_wmi_datetime_to_datetime(wmi_date: &str) -> Result<NaiveDateTime, ParseError> { 
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

fn get_process_details(process_id: u32) -> Result<HashMap<String, Variant>, Box<dyn std::error::Error>> {
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
