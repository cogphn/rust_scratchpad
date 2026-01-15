use windows::Win32::System::Threading::{GetProcessIdOfThread, OpenThread, THREAD_QUERY_LIMITED_INFORMATION };
use argparse::ArgumentParser;
use argparse::Store;
use wmi::{WMIConnection};

use serde::Deserialize;
use serde::Serialize;

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

    let wmi_con = match WMIConnection::new(){
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



fn main() -> Result<(), Box <dyn std::error::Error>>{
    println!("[*] starting...");

    let mut thread_id = 0;
    {
        let mut ap = ArgumentParser::new();
        ap.set_description("Process lookup");
        ap.refer(&mut thread_id)
            .add_option(&["-t","--tid"], 
            Store,
            "thread id"
        ).required();
       
        ap.parse_args_or_exit();
    }

    
    if thread_id != 0 {
        println!("  [*] thread id: {}", thread_id);

        unsafe {
            println!("  [*] getting thread handle...");
            let thread_handle = OpenThread( THREAD_QUERY_LIMITED_INFORMATION, false, thread_id)?;
            println!("  [*] getting process id...");
            let process_id = GetProcessIdOfThread(thread_handle);
            println!("PID: {}", process_id);
            let process_details = get_process_by_id(process_id);
            println!("{:?}", process_details);
        }
        
        
    }


    println!("[.] Done!");

    Ok(())

}
