//use wmi::{COMLibrary, WMIConnection};
use wmi::{WMIConnection};
use netstat_esr::{get_sockets_info, AddressFamilyFlags, ProtocolFlags, ProtocolSocketInfo};
use serde::{Serialize, Deserialize};
use chrono::NaiveDateTime;
use winreg::enums::*;
use winreg::RegKey;
use log::error;

use super::rtevents;
use super::parser;

#[derive(Serialize, Deserialize, Debug)]
pub struct Netconn {
    pub hostname: String,
    pub conntype: String,
    pub local_address: String,
    pub local_port: u16,
    pub remote_address: String,
    pub remote_port: u16,
    pub state: String,
    pub associated_pids: Vec<u32>, //not sure I need this if I have associated_processes
    pub associated_processes: Vec<rtevents::Process>
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ServiceReg {
    pub sk_name: String,
    pub display_name: String, 
    pub error_control: u32, 
    pub image_path: String,
    pub owners: String, 
    pub start: u32,
    pub service_type: u32,
    pub key_last_modified: NaiveDateTime
}


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
  pub install_date: Option<String>,
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



pub fn get_process_list() -> Result<Vec<rtevents::ProcessInfo>, Box<dyn std::error::Error>> {
    let wmi_conn = WMIConnection::new()?;
    
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

pub fn get_netconn_list() -> Result<Vec<Netconn>, Box<dyn std::error::Error>> {
    let af_flags = AddressFamilyFlags::IPV4 | AddressFamilyFlags::IPV6;
    let proto_flags = ProtocolFlags::TCP | ProtocolFlags::UDP;
    let sockets_info = get_sockets_info(af_flags, proto_flags).unwrap();

    let hostname = rtevents::get_hostname();

    let netconn_list: Vec<Netconn> = sockets_info
        .into_iter()
        .map(|si| {
            let process_id_list = si.associated_pids.clone();

            let conn_process_list: Vec<rtevents::Process> = process_id_list.into_iter().map(|pid|{
                rtevents::get_process_by_id(pid)
            }).collect();

            let mut nc = Netconn {
                hostname: hostname.clone(),
                conntype: "*NA".to_string(),
                local_address: "0.0.0.0".to_string(),
                local_port: 0,
                remote_address: "0.0.0.0".to_string(),
                remote_port: 0,
                state: "*NA".to_string(),
                associated_pids: vec![0],
                associated_processes: conn_process_list
            };

            match si.protocol_socket_info {
                ProtocolSocketInfo::Udp(usi) => {
                    nc.conntype = "UDP".to_string();
                    nc.local_address = usi.local_addr.to_string();
                    nc.local_port = usi.local_port; 
                    nc.remote_address = usi.remote_addr.to_string(); 
                    nc.remote_port = usi.remote_port;
                    nc.associated_pids = si.associated_pids;
                },  
                ProtocolSocketInfo::Tcp(tsi) => {
                    nc.conntype = "TCP".to_string();
                    nc.local_address = tsi.local_addr.to_string();
                    nc.local_port = tsi.local_port;
                    nc.remote_address = tsi.remote_addr.to_string();
                    nc.remote_port = tsi.remote_port;
                    nc.state = tsi.state.to_string();
                    nc.associated_pids = si.associated_pids;
                }
            };
            nc
        }).collect();

        return Ok(netconn_list);
}

pub fn get_service_list() -> Result<Vec<Service>, Box<dyn std::error::Error>> {
    let wmi_conn = WMIConnection::new()?;    
    let services: Vec<Service> = wmi_conn.query()?;
    // TODO: enrich or dump reg list separately? :think-emoji:
    return Ok(services);
}


pub fn get_service_list_winreg() -> Vec<ServiceReg> {
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let sk_txt = "SYSTEM\\CurrentControlSet\\Services";
    let mut ret: Vec<ServiceReg> = vec![];

    let service_subkeys_result = RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey(sk_txt);

    let service_subkeys = match service_subkeys_result {
        Err(e) => {
            error!("[!] error opening services subkey: {}", e);
            return ret;
        },
        Ok(subkeys) => subkeys
    };

    for ssk in service_subkeys.enum_keys() {
        match ssk {
            Ok(svc_sk) => {
                let service_subkey_txt = sk_txt.to_owned() + "\\" + &svc_sk;
                match hklm.open_subkey(service_subkey_txt) {
                    Err(e) => {
                        error!("[!] error opening subkey for windows service: {}", e);
                        continue;
                    },
                    Ok(v) => {
                        let service_subkey = v;


                        let service_subkey_info = match service_subkey.query_info() {
                            Err(e) => {
                                error!("[!] error getting registry key info: {}", e);
                                continue;
                            }, Ok(sski) => sski
                        };


                        let s: ServiceReg  = ServiceReg {
                            sk_name: svc_sk,
                            display_name: service_subkey.get_value("DisplayName").unwrap_or("".to_string()),
                            error_control: service_subkey.get_value("ErrorControl").unwrap_or(0),
                            image_path: service_subkey.get_value("ImagePath").unwrap_or("".to_string()),
                            owners: service_subkey.get_value("Owners").unwrap_or("".to_string()),
                            start:  service_subkey.get_value("Start").unwrap_or(0),
                            service_type:  service_subkey.get_value("Type").unwrap_or(0),
                            key_last_modified: service_subkey_info.get_last_write_time_chrono()
                        };
                        ret.push(s);
                    }
                }
            },
            Err(e) => {
                error!("[!] error getting sub-key for windows service: {}", e);
                continue;
            }
        } 
    }

    //for svc in RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey(sk_txt)
    return ret;
}