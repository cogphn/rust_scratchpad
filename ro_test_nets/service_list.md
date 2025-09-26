### Cargo.toml
~~~toml
[package]
name = "svclist"
version = "0.1.0"
edition = "2024"

[dependencies]
wmi = "0.17.2"
serde = { version = "1.0", features = ["derive"] }
~~~

### main.rs
~~~rust
use wmi::{COMLibrary, WMIConnection, WMIDateTime};
use serde::Deserialize;
use serde::Serialize;

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename = "Win32_Service")] 
#[serde(rename_all = "PascalCase")]
pub struct Service {
  accept_pause: bool,
  accept_stop: bool  ,
  caption: Option<String>,
  check_point: u32   ,
  creation_class_name: Option<String>,
  delayed_auto_start: bool,
  description: Option<String>,
  desktop_interact: bool,
  display_name: Option<String>,
  error_control: Option<String>,
  exit_code: u32   ,
  install_date: Option<WMIDateTime>,
  name: Option<String>,
  path_name: Option<String>,
  process_id: u32   ,
  service_specific_exit_code: u32   ,
  service_type: Option<String>,
  started: bool,
  start_mode: Option<String>,
  start_name: Option<String>,
  state: Option<String>,
  status: Option<String>,
  system_creation_class_name: Option<String>,
  system_name: Option<String>,
  tag_id: u32,
  wait_hint: u32,
}

pub fn get_service_list() -> Result<Vec<Service>, Box<dyn std::error::Error>> {
    let com_lib = COMLibrary::new()?;
    let wmi_conn = WMIConnection::new(com_lib)?;    
    let services: Vec<Service> = wmi_conn.query()?;
    return Ok(services);
}

fn main() {
    println!("[*] starting...");
    let services = get_service_list();

    match services {
        Ok(service_list) => {
            println!("{:?}", service_list);
        },
        Err(err) => println!("[!] presumably some error occured: {:?}", err),
    };

    println!("[.] done");
}

~~~
