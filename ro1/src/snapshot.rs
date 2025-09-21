//use chrono::{DateTime, Utc, NaiveDateTime, ParseError }; //, ParseError};
use wmi::{COMLibrary, WMIConnection};

use super::rtevents;
use super::parser;





pub fn get_process_list() -> Result<Vec<rtevents::ProcessInfo>, Box<dyn std::error::Error>> {
    let com_lib = COMLibrary::new()?;
    let wmi_conn = WMIConnection::new(com_lib)?;
    
    let processes: Vec<rtevents::Process> = wmi_conn.query()?;

    let hostname = rtevents::get_hostname();

    let process_infos: Vec<rtevents::ProcessInfo> = processes
        .into_iter()
        .map(|p| { 
            let cd = p.creation_date.unwrap_or("1970-01-01T00:00:00".to_string());
            rtevents::ProcessInfo { 
                hostname: hostname.clone(),
                executable_path: p.executable_path.unwrap_or("*NA".to_string()),
                process_id: p.process_id as u32,
                creation_date: parser::convert_wmi_datetime_to_datetime(&cd).expect("1970-01-01T00:00:00"),
                creation_date_utc: parser::convert_wmi_datetime_to_datetime_utc(&cd).expect("1970-01-01T00:00:00"),
                command_line: p.command_line.unwrap_or("*NA".to_string()),
                name: p.name,
                parent_process_id: p.parent_process_id.unwrap_or(0),
                description: p.description.unwrap_or("*NA".to_string()),
                handle: p.handle.unwrap_or("*NA".to_string()),
                handle_count: p.handle_count.unwrap_or(0),
                os_name: p.os_name.unwrap_or("*NA".to_string()),
                windows_version: p.windows_version.unwrap_or("*NA".to_string()),
                session_id: p.session_id.unwrap_or(0)
            }
        }).collect();
    
    return Ok(process_infos);
}

