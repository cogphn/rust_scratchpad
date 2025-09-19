
use chrono::{DateTime, Utc, NaiveDateTime, ParseError }; //, ParseError};
use super::cache;
use super::rtevents;
use wmi::{Variant};
use std::collections::HashMap;

use rtevents::etwevents::templates;


pub fn convert_wmi_datetime_to_datetime(wmi_date: &str) -> Result<NaiveDateTime, ParseError> { 
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



pub fn proc_hm_to_pi(process: &HashMap<String, Variant>, classname: &str) -> Result<rtevents::ProcessInfo, Box<dyn std::error::Error>> {
    
    let hostname = rtevents::get_hostname();
    let mut newproc: rtevents::ProcessInfo = rtevents::ProcessInfo { 
        name: "*NA".to_string(),
        hostname: hostname,
        command_line: "*NA".to_string(),
        parent_process_id: 0,
        process_id: 0,
        creation_date: NaiveDateTime::parse_from_str("1970-01-01T00:00:00", "%Y-%m-%dT%H:%M:%S").unwrap(),
        executable_path:"*NA".to_string(),
        description: "*NA".to_string(),        
        handle: "*NA".to_string(),        
        handle_count: 0,
        os_name: "*NA".to_string(),
        windows_version: "*NA".to_string(),
        session_id: 0        
    };
    
    if classname == "Win32_Process" {
        newproc.name = match process.get("Name") {
            Some(Variant::String(s)) => s.to_string(),
            _ => "*NA".to_string(),
        };

        newproc.command_line = match process.get("CommandLine") {
            Some(Variant::String(s)) => s.to_string(),
            Some(Variant::Null) => "None".to_string(),
            _ => "*NA".to_string(),
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
            Some(Variant::String(s)) => convert_wmi_datetime_to_datetime(&s).unwrap(),            
            _ => NaiveDateTime::parse_from_str("1970-01-01T00:00:00", "%Y-%m-%dT%H:%M:%S").unwrap(),
        };
        newproc.description = match process.get("Description") {
            Some(Variant::String(s)) => s.to_string(),
            Some(Variant::Null) => "*NA".to_string(),
            _ => "*NA".to_string(),
        };

        newproc.executable_path = match process.get("ExecutablePath") {
            Some(Variant::String(s)) => s.to_string(),
            Some(Variant::Null) => "None".to_string(),
            _ => "*NA".to_string(),
        };
        
        newproc.handle = match process.get("Handle") {
            Some(Variant::String(s)) => s.to_string(),
            _ => "*NA".to_string(),
        };

        newproc.session_id = match process.get("SessionId") {
            Some(Variant::UI4(id)) => *id,
            Some(Variant::Null) => 0,
            _ => 0,
        };
        

    } else if classname == "Win32_ProcessStartTrace" {
       
        newproc.name = match process.get("ProcessName") {
            Some(Variant::String(s)) => s.to_string(),
            _ => "*NA".to_string(),
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
         
        let process_details = rtevents::get_process_details(newproc.process_id);
        
        newproc.command_line = match &process_details{ //TODO: fix 
            Ok(details) => match details.get("CommandLine") {
                Some(Variant::String(s)) => s.to_string(),
                Some(Variant::Null) => "*NA".to_string(),
                _ => "*NA".to_string(),
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

        newproc.description = match &process_details{
            Ok(details) => match details.get("Description") {
                Some(Variant::String(s)) => s.to_string(),
                Some(Variant::Null) => "*NA".to_string(),
                _ => "*NA".to_string(),
            },            
            Err(_) => "*NA".to_string(),
        };

        newproc.executable_path = match &process_details{
            Ok(details) => match details.get("ExecutablePath") {
                Some(Variant::String(s)) => s.to_string(),
                Some(Variant::Null) => "*NA".to_string(),
                _ => "*NA".to_string(),
            },            
            Err(_) => "*NA".to_string(),
        };

        newproc.handle = match &process_details{
            Ok(details) => match details.get("Handle") {
                Some(Variant::String(s)) => s.to_string(),
                _ => "*NA".to_string(),
            },            
            Err(_) => "*NA".to_string(),
        };

        newproc.session_id = match &process_details{
            Ok(details) => match details.get("SessionId") {
                Some(Variant::UI4(id)) => *id,
                Some(Variant::Null) => 0,
                _ => 0,
            },            
            Err(_) => 0,
        };

        newproc.os_name = match &process_details{
            Ok(details) => match details.get("OSName") {
                Some(Variant::String(s)) => s.to_string(),
                Some(Variant::Null) => "*NA".to_string(),
                _ => "*NA".to_string(),
            },            
            Err(_) => "*NA".to_string(),
        };

    }
    
    return Ok(newproc);

}


pub fn pi_to_er(pi:&rtevents::ProcessInfo, procsrc: &str) -> Result<cache::GenericEventRecord, Box<dyn std::error::Error>> {
    let ret  = cache::GenericEventRecord {
        ts: pi.creation_date,
        src: procsrc.to_string(),
        host: pi.hostname.clone(),
        context1: pi.name.clone(),
        context1_attrib: "ProcessName".to_string(),
        context2: pi.process_id.to_string(),
        context2_attrib: "PID".to_string(),
        context3: pi.parent_process_id.to_string(),
        context3_attrib: "PPID".to_string(),
        //rawevent: format!("Path: {}, CommandLine: {}", pi.executable_path, pi.command_line)
        rawevent: serde_json::to_string(pi).unwrap()
    };
    Ok(ret)
}


pub fn wel_json_to_er(event_str: &str) -> Result<cache::GenericEventRecord, Box<dyn std::error::Error>> {
    let mut ret  = cache::GenericEventRecord {
        ts: NaiveDateTime::parse_from_str("1970-01-01T00:00:00", "%Y-%m-%dT%H:%M:%S")?,
        src: "WELS".to_string(),
        host: "N/A".to_string(),
        context1: "N/A".to_string(),
        context1_attrib: "N/A".to_string(),
        context2: "N/A".to_string(),
        context2_attrib: "N/A".to_string(),
        context3: "N/A".to_string(),
        context3_attrib: "N/A".to_string(),
        rawevent: event_str.to_string()
    };

    let event_json = serde_json::from_str::<serde_json::Value>(event_str).unwrap();
    let system_json_array = &event_json["Event"]["#c"][0]["System"]["#c"];
    let system_json_array = system_json_array.as_array();
    /*
    "Provider", "EventID", "Version", "Level", "Task", "Opcode", "Keywords", "TimeCreated",
    "EventRecordID", "Correlation", "Execution", "Channel", "Computer", "Security" ,     
    */
    for a in system_json_array.iter() {
        for val in a.iter() {
            for k in val.as_object().expect("INVALID").keys() {
                match k.as_str() {
                    "Channel" => {
                        ret.context1 = val["Channel"]["#t"]
                            .as_str()
                            .unwrap_or("N/A")
                            .to_string();
                        ret.context1_attrib = "Channel".to_string();
                    },
                    "Provider" => {
                        ret.context2 = val["Provider"]["@Name"]
                            .as_str()
                            .unwrap_or("N/A")
                            .to_string();
                        ret.context2_attrib = "Provider".to_string();
                    },
                    "EventID" => {
                        ret.context3 = val["EventID"]["#t"]
                            .as_str()
                            .unwrap_or("N/A")
                            .to_string(); 
                        ret.context3_attrib = "EID".to_string();
                    },
                    "Computer" => {
                        ret.host = val["Computer"]["#t"]
                            .as_str()
                            .unwrap_or("N/A")
                            .to_string();                        
                    },
                    "TimeCreated" => {
                        let ts_str = val["TimeCreated"]["@SystemTime"].to_string();
                        let ts_str_cleaned = &ts_str.trim_matches('"');
                        let parsed_datetime = DateTime::parse_from_rfc3339(&ts_str_cleaned).expect("1970-01-01T00:00:00").with_timezone(&Utc);
                        let _ = match DateTime::parse_from_rfc3339(&ts_str_cleaned) {
                            Ok(_dt) => {
                                ret.ts = parsed_datetime.naive_utc()
                            },
                            Err(_) => {
                                ret.ts = NaiveDateTime::parse_from_str("1970-01-01T00:00:00", "%Y-%m-%dT%H:%M:%S").unwrap()
                            }
                        };
                        
                    },
                    _ => {}
                }
            }
        }
    }
    Ok(ret)

}


pub fn netevent_to_er(netevent: templates::GeneralNetEvent) -> Result<cache::GenericEventRecord, Box<dyn std::error::Error>> {

    let mut ret  = cache::GenericEventRecord {
        ts: NaiveDateTime::parse_from_str("1970-01-01T00:00:00", "%Y-%m-%dT%H:%M:%S")?,
        //ts: NaiveDateTime::parse_from_str(&netevent.ts_str, "%Y-%m-%d %H:%M:%S")?,
        src: "ETW_MSWINTCP".to_string(),
        host: "N/A".to_string(),
        context1: "".to_string(),
        context1_attrib: "event_id".to_string(),
        context2: "N/A".to_string(),
        context2_attrib: "provider_name".to_string(),
        context3: "N/A".to_string(),
        context3_attrib: "remote_address_ipv4".to_string(),
        rawevent: serde_json::to_string(&netevent).unwrap()
    };


    let ts_utc = netevent.ts_str.split(" +").collect::<Vec<_>>()[0]; // TODO: rethink
    ret.ts = match NaiveDateTime::parse_from_str(ts_utc, "%Y-%m-%d %H:%M:%S%.f"){
        Ok(v) => v,
        Err(_) => NaiveDateTime::parse_from_str("1970-01-01T00:00:00", "%Y-%m-%dT%H:%M:%S")?
    };

    ret.host = rtevents::get_hostname(); //I'm not sure why I can't get this from the tracing event itself
    ret.context1 = netevent.event_id.to_string();
    ret.context2 = netevent.provider_name;
    ret.context3 = netevent.remote_address_ipv4;

    Ok(ret)
}


pub fn dnsevent_to_er(dnsevent: templates::GenericDnsEvent) ->  Result<cache::GenericEventRecord, Box<dyn std::error::Error>> {

    let mut ret = cache::GenericEventRecord {
        ts: NaiveDateTime::parse_from_str("1970-01-01T00:00:00", "%Y-%m-%dT%H:%M:%S")?,
        src: "ETW_MSWINDNS".to_string(),
        host: "*NA".to_string(),
        context1: "".to_string(),
        context1_attrib: "event_id".to_string(),
        context2: "*NA".to_string(),
        context2_attrib: "provider_name".to_string(),
        context3: "*NA".to_string(),
        context3_attrib: "query_name".to_string(),
        rawevent: serde_json::to_string(&dnsevent).unwrap()
    };

    let ts_utc = dnsevent.ts_str.split(" +").collect::<Vec<_>>()[0]; // TODO: rethink
    ret.ts = match NaiveDateTime::parse_from_str(ts_utc, "%Y-%m-%d %H:%M:%S%.f"){
        Ok(v) => v,
        Err(_) => NaiveDateTime::parse_from_str("1970-01-01T00:00:00", "%Y-%m-%dT%H:%M:%S")?
    };

    ret.host = rtevents::get_hostname();
    ret.context1 = dnsevent.event_id.to_string();
    ret.context2 = dnsevent.provider_name;
    ret.context3 = match dnsevent.query_name {
        Some(s) => s,
        None => "*NA".to_string()
    };
    Ok(ret)

}


pub fn regevent_to_er(regevent: templates::GenericRegEvent) ->  Result<cache::GenericEventRecord, Box<dyn std::error::Error>> {

    let mut ret = cache::GenericEventRecord {
        ts: NaiveDateTime::parse_from_str("1970-01-01T00:00:00", "%Y-%m-%dT%H:%M:%S")?,
        src: "ETW_MSWINREG".to_string(),
        host: "*NA".to_string(),
        context1: "".to_string(),
        context1_attrib: "event_id".to_string(),
        context2: "*NA".to_string(),
        context2_attrib: "provider_name".to_string(),
        context3: "*NA".to_string(),
        context3_attrib: "relative_name".to_string(),
        rawevent: serde_json::to_string(&regevent).unwrap()
    };

    ret.ts = match NaiveDateTime::parse_from_str(&regevent.ts_str, "%Y-%m-%dT%H:%M:%SZ"){
        Ok(v) => v,
        Err(_) => NaiveDateTime::parse_from_str("1970-01-01T00:00:00", "%Y-%m-%dT%H:%M:%S")?
    };

    ret.host = rtevents::get_hostname();
    ret.context1 = regevent.event_id.to_string();
    ret.context2 = regevent.provider_name;
    ret.context3 = match regevent.relative_name {
        Some(s) => s,
        None => "*NA".to_string()
    };
    Ok(ret)

}
