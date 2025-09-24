//use chrono::{DateTime, Utc, NaiveDateTime, ParseError }; //, ParseError};
use wmi::{COMLibrary, WMIConnection};

use netstat_esr::{get_sockets_info, AddressFamilyFlags, ProtocolFlags, ProtocolSocketInfo};
use serde::{Serialize, Deserialize};

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
    pub associated_pids: Vec<u32>,
    pub associated_processes: Vec<rtevents::Process>
}




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
