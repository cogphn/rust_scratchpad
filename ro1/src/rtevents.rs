use serde::Deserialize;
use wmi::{COMLibrary, WMIConnection};


#[derive(Deserialize, Debug)]
#[serde(rename = "Win32_Process")] // Maps to the WMI class name
#[serde(rename_all = "PascalCase")] // WMI properties are typically PascalCase
struct Process {
    process_id: u32,
    name: String,
    executable_path: Option<String>,
    command_line: Option<String>,
    parent_process_id: u32
    // Add other properties you need, e.g., command_line, parent_process_id
}


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
