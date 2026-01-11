
use wmi::WMIDateTime;
//use wmi::{COMLibrary, WMIConnection};
use wmi::{ WMIConnection};
use serde::{Serialize, Deserialize};



#[derive(Serialize, Deserialize, Debug)]
#[serde(rename = "Win32_Service")] 
#[serde(rename_all = "PascalCase")]
pub struct Service {
  pub accept_pause: bool,
  pub accept_stop: bool  ,
  pub caption: Option<String>,
  pub check_point: u32   ,
  pub creation_class_name: Option<String>,
  pub delayed_auto_start: bool,
  pub description: Option<String>,
  pub desktop_interact: bool,
  pub display_name: Option<String>,
  pub error_control: Option<String>,
  pub exit_code: u32   ,
  pub install_date: Option<WMIDateTime>,
  pub name: Option<String>,
  pub path_name: Option<String>,
  pub process_id: u32   ,
  pub service_specific_exit_code: u32,
  pub service_type: Option<String>,
  pub started: bool,
  pub start_mode: Option<String>,
  pub start_name: Option<String>,
  pub state: Option<String>,
  pub status: Option<String>,
  pub system_creation_class_name: Option<String>,
  pub system_name: Option<String>,
  pub tag_id: u32,
  pub wait_hint: u32,
}


fn get_service_list() -> Result<Vec<Service>, Box<dyn std::error::Error>> {
    //let com_lib = COMLibrary::new()?;
    //let wmi_conn = WMIConnection::new(com_lib)?;    
    let wmi_conn = WMIConnection::new()?;    
    let services: Vec<Service> = wmi_conn.query()?;
    return Ok(services);
}

fn main() -> Result<(), Box <dyn std::error::Error>> {
    let service_list = get_service_list()?;

    println!("{:?}", service_list);

    /*
    for svc in service_list {
        println!("Install date: {:?}", svc.install_date);
    }
        */

    Ok(())
}
