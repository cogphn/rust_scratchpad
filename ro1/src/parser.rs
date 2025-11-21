use chrono::{NaiveDate, NaiveTime};
use chrono::{DateTime, Utc, NaiveDateTime, ParseError, Local }; 
use super::cache;
use super::rtevents;
use super::snapshot;
use wmi::{Variant};
use std::collections::HashMap;
use serde_json::{Map,Value,json};
use rtevents::etwevents::templates;


pub fn get_default_date() -> NaiveDateTime {
    let dd = NaiveDate::from_ymd_opt(1970, 01, 01).unwrap();
    let dt = NaiveTime::from_hms_opt(0, 0, 0).unwrap();
    return NaiveDateTime::new(dd, dt);
}

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

pub fn convert_wmi_datetime_to_datetime_utc(wmi_date: &str) -> Result<NaiveDateTime, ParseError> { 
    if wmi_date.len() < 14 {
        return NaiveDateTime::parse_from_str("1970-01-01T00:00:00", "%Y-%m-%dT%H:%M:%S");
    }
    
    let dt_str = &wmi_date[0..14];
    if let Ok(naive_dt) = NaiveDateTime::parse_from_str(dt_str, "%Y%m%d%H%M%S") {
        let dt_utc = naive_dt.and_local_timezone(Local).unwrap();
        return Ok(dt_utc.naive_utc());
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
        creation_date_utc: NaiveDateTime::parse_from_str("1970-01-01T00:00:00", "%Y-%m-%dT%H:%M:%S").unwrap(),
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
        let cd_str = match process.get("CreationDate") {
            Some(Variant::String(s)) => s,
            _ => &"1970-01-01T00:00:00".to_string()
        };
        let default_dt = get_default_date();
        newproc.creation_date = convert_wmi_datetime_to_datetime(&cd_str).unwrap_or(default_dt);
        newproc.creation_date_utc = convert_wmi_datetime_to_datetime_utc(&cd_str).unwrap_or(default_dt);

        
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

        let cd_str = match &process_details {
            Ok(procdetails) => match procdetails.get("CreationDate") {
                Some(Variant::String(s)) => s,
                _ => "1970-01-01T00:00:00"
            },
            Err(_) => "1970-01-01T00:00:00"
        };

        //let default_date = NaiveDateTime::new(NaiveDate::from_ymd_opt(1970, 01, 01), NaiveTime::from_hms_opt(0,0,0));
        newproc.creation_date = convert_wmi_datetime_to_datetime(&cd_str).unwrap();
        newproc.creation_date_utc = convert_wmi_datetime_to_datetime_utc(&cd_str).unwrap();

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
        id: None,
        ts: pi.creation_date_utc,
        ts_type: "process_creation_date".to_string(),
        src: procsrc.to_string(),
        host: pi.hostname.clone(),
        context1: pi.name.clone(),
        context1_attrib: "ProcessName".to_string(),
        context2: pi.process_id.to_string(),
        context2_attrib: "PID".to_string(),
        context3: pi.parent_process_id.to_string(),
        context3_attrib: "PPID".to_string(),
        rawevent: serde_json::to_string(pi).unwrap()
    };
    Ok(ret)
}

fn get_wel_values(obj: &Map<String, Value>, key: &String, mut parentkey: String) -> Vec<Map<String, Value>>  {
    let val = obj[key].clone();
    parentkey = parentkey.replace("#c\\", "");
    if key == "#t" {
        let mut ret = serde_json::Map::new();
        ret.insert(parentkey, val);
        return vec![ret]; 
    }    
    match &val {
        Value::Object(map) =>  {
            let mut ret = vec![];
            for topkey in map.keys() {
                let mut r1 = get_wel_values(map, topkey, (parentkey.clone() + "\\"+ key).to_string());
                ret.append(&mut r1);
            }
            return ret;
        },
        Value::Array(_arr) =>  {
            if let Some(data_array) = val.as_array() {
                let mut ret = vec![];
                for a in data_array{
                    match a {
                        Value::Object(ar_obj) => {
                            for topkey in ar_obj.keys() {
                                let mut r1 = get_wel_values(ar_obj, topkey, (parentkey.clone() + "\\"+ key).to_string());
                                ret.append(&mut r1);
                            }
                        },                        
                        Value::String(str) => {                            
                            let mut r1 = Map::new();
                            r1.insert(parentkey.clone(), json!(str));
                            ret.append(&mut vec![r1]);
                        },
                        Value::Null => {},
                        _ => {
                            println!("[!] TODO: match more types");
                        }
                    }
                }
                return ret;
            } else {
                return vec![]; // maybe this never happens
            }
        },
        Value::String(str) => {
            let mut r1 = serde_json::Map::new();
            let v = json!(str);            
            r1.insert(key.to_string(), v);
            return vec![r1];

        },
        _ => {
            println!("[!]: match more values here ");
            return vec![];
        }
    }    
}

fn wel_raw_to_obj(wels_raw: String) -> Result<serde_json::Map<String, serde_json::Value>, serde_json::Error> {
    let wels_obj: Result<serde_json::Value, serde_json::Error> = serde_json::from_str(&wels_raw);

    let obj = match wels_obj {
        Err(e) => {
            return Err(e);
        },
        Ok(val) => {val}
    };
    
    let mut ret = serde_json::Map::new();

    if let serde_json::Value::Object(map) = &obj["Event"] {
        for topkey in map.keys() {
            let x = get_wel_values(map, topkey, "<root>".to_string());
            let mut kresolver = 1;
            for obj in x.clone().into_iter() {
                for k in obj.keys() {
                    if obj[k] == "(NULL)"{
                        continue;
                    }                        
                    if k.starts_with("<root>\\System") {                        
                        let mut nk =k.replace("<root>\\System\\", "");
                        nk = nk.replace("@","");
                        ret.insert(nk, obj[k].clone());
                    } else {
                        let mut nk = k.replace("<root>\\","");
                        nk = nk.replace("@", "");
                        if ret.contains_key(&nk) {                            
                            nk = nk + &kresolver.to_string();
                            kresolver += 1;                            
                        }
                        ret.insert(nk, obj[k].clone());
                        
                    }                    
                }
            }
        }
    }


    Ok(ret)

}


pub fn wel_json_to_er(event_str: &str) -> Result<cache::GenericEventRecord, Box<dyn std::error::Error>> {
    let mut ret  = cache::GenericEventRecord {
        id: None,
        ts: NaiveDateTime::parse_from_str("1970-01-01T00:00:00", "%Y-%m-%dT%H:%M:%S")?,
        ts_type: "creation_time".to_string(),
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

    let wel_rawobj = wel_raw_to_obj(event_str.to_string());

    match wel_rawobj {
        Err(_e) => {},
        Ok(parsed_obj) => {
            let parsed_str = serde_json::to_string(&parsed_obj);
            match parsed_str{
                Err(_err) => {},
                Ok(parsed) => {ret.rawevent = parsed;}
            }
        }
    }
    

    let event_json = serde_json::from_str::<serde_json::Value>(event_str).unwrap();
    let system_json_array = &event_json["Event"]["#c"][0]["System"]["#c"];
    let system_json_array = system_json_array.as_array();
    
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
        id: None,
        ts: NaiveDateTime::parse_from_str("1970-01-01T00:00:00", "%Y-%m-%dT%H:%M:%S")?,
        ts_type: "netevent_timestamp".to_string(),
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


    //let ts_utc = netevent.ts_str.split(" +").collect::<Vec<_>>()[0]; // TODO: rethink
    ret.ts = match NaiveDateTime::parse_from_str(&netevent.ts_str, "%Y-%m-%dT%H:%M:%SZ"){
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
        id: None,
        ts: NaiveDateTime::parse_from_str("1970-01-01T00:00:00", "%Y-%m-%dT%H:%M:%S")?,
        ts_type: "dnsevent_timestamp".to_string(),
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

    
    ret.ts = match NaiveDateTime::parse_from_str(&dnsevent.ts_str, "%Y-%m-%dT%H:%M:%SZ"){
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
        id: None,
        ts: NaiveDateTime::parse_from_str("1970-01-01T00:00:00", "%Y-%m-%dT%H:%M:%S")?,
        ts_type: "regevent_timestamp".to_string(),
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


pub fn fileevent_to_er(filevent: templates::GenericFileEvent) ->  Result<cache::GenericEventRecord, Box<dyn std::error::Error>> {

    let mut ret = cache::GenericEventRecord {
        id: None,
        ts: NaiveDateTime::parse_from_str("1970-01-01T00:00:00", "%Y-%m-%dT%H:%M:%S")?,
        ts_type: "filevent_timestamp".to_string(),
        src: "ETW_MSWINFILE".to_string(),
        host: "*NA".to_string(),
        context1: "".to_string(),
        context1_attrib: "event_id".to_string(),
        context2: "*NA".to_string(),
        context2_attrib: "provider_name".to_string(),
        context3: "*NA".to_string(),
        context3_attrib: "file_name".to_string(),
        rawevent: serde_json::to_string(&filevent).unwrap()
    };

    ret.ts = match NaiveDateTime::parse_from_str(&filevent.ts_str, "%Y-%m-%dT%H:%M:%SZ"){
        Ok(v) => v,
        Err(_) => NaiveDateTime::parse_from_str("1970-01-01T00:00:00", "%Y-%m-%dT%H:%M:%S")?
    };

    ret.host = rtevents::get_hostname();
    ret.context1 = filevent.event_id.to_string();
    ret.context2 = filevent.provider_name;
    ret.context3 = match filevent.file_name {
        Some(s) => s,
        None => "*NA".to_string()
    };
    Ok(ret)

}


pub fn netconn_to_er(netconn: snapshot::Netconn) -> Result<cache::GenericEventRecord, Box<dyn std::error::Error>> {
    
    let mut ret = cache::GenericEventRecord {
        id: None,
        ts: NaiveDateTime::parse_from_str("1970-01-01T00:00:00", "%Y-%m-%dT%H:%M:%S")?,
        ts_type: "netevent_timestamp".to_string(),
        src: "NETCONN".to_string(),
        host: "*NA".to_string(),
        context1: "0.0.0.0".to_string(),
        context1_attrib: "local_address".to_string(),
        context2: "0.0.0.0".to_string(),
        context2_attrib: "remote_address".to_string(),
        context3: "*NA".to_string(),
        context3_attrib: "conntype".to_string(),
        rawevent: serde_json::to_string(&netconn).unwrap()
    };

    ret.host = rtevents::get_hostname();
    ret.context1 = netconn.local_address;
    ret.context2 = netconn.remote_address;
    ret.context3 = netconn.conntype;

    if netconn.associated_processes.len() >= 1 {
        let proc0 = &netconn.associated_processes[0]; //only gets the first process
        let tsstr = match &proc0.creation_date {
            Some(s) => s,
            _ => &"1970-01-01T00:00:00".to_string()
        };
        ret.ts = convert_wmi_datetime_to_datetime_utc(&tsstr).unwrap();
        ret.ts_type = "process_creation_timestamp".to_string();
    }

    Ok(ret)

}


pub fn service_to_er(svc: snapshot::Service) -> Result<cache::GenericEventRecord, Box<dyn std::error::Error>> {
    
    let mut ret = cache::GenericEventRecord {
        id: None,
        ts: NaiveDateTime::parse_from_str("1970-01-01T00:00:00", "%Y-%m-%dT%H:%M:%S")?,
        ts_type: "service_install_date".to_string(),
        src: "SVCLIST".to_string(),
        host: "*NA".to_string(),
        context1: "*NA".to_string(),
        context1_attrib: "name".to_string(),
        context2: "*NA".to_string(),
        context2_attrib: "path_name".to_string(),
        context3: "*NA".to_string(),
        context3_attrib: "status".to_string(),
        rawevent: serde_json::to_string(&svc).unwrap()
    };


    match svc.install_date {
        Some(install_date) => {
            ret.ts = match NaiveDateTime::parse_from_str(&install_date, "%Y-%m-%dT%H:%M:%SZ"){
                Ok(v) => v,
                Err(_) => NaiveDateTime::parse_from_str("1970-01-01T00:00:00", "%Y-%m-%dT%H:%M:%S")?
            };
        },
        None => ret.ts = NaiveDateTime::parse_from_str("1970-01-01T00:00:00", "%Y-%m-%dT%H:%M:%S")?,
    };

    ret.host = rtevents::get_hostname();

    ret.context1 = match svc.name { 
        Some(name) => name,
        None => "*NA".to_string()
    };
    
    ret.context2 = match svc.path_name {
        Some(path_name) => path_name,
        None => "*NA".to_string()
    };
    
    ret.context3 = match svc.status {
        Some(status) => status,
        None => "*NA".to_string()
    };
    
    Ok(ret)   

}
