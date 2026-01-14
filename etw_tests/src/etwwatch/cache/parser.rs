use chrono::{NaiveDate, NaiveTime};
use chrono::{DateTime, Utc, NaiveDateTime, ParseError, Local }; 

use std::collections::HashMap;
//use serde_json::{Map,Value,json};

//use crate::cache::templates;
use crate::cache;


pub fn get_default_date() -> NaiveDateTime {
    let dd = NaiveDate::from_ymd_opt(1970, 01, 01).unwrap();
    let dt = NaiveTime::from_hms_opt(0, 0, 0).unwrap();
    return NaiveDateTime::new(dd, dt);
}

pub fn dng_to_er(etwevent: cache::templates::DotnetEvent) -> Result<cache::GenericEventRecord, Box<dyn std::error::Error>> {

    let mut ret = cache::GenericEventRecord {
        id: None,
        ts: NaiveDateTime::parse_from_str("1970-01-01T00:00:00", "%Y-%m-%dT%H:%M:%S")?,
        ts_type: "etw_ts".to_string(),
        src: "dotnet_generic".to_string(),
        host: "*NA".to_string(),
        context1: "".to_string(),
        context1_attrib: "clr_instance_id".to_string(),
        context2: "".to_string(),
        context2_attrib: "runtime_dll_path".to_string(),
        context3: "*NA".to_string(),
        context3_attrib: "command_line".to_string(),
        rawevent: serde_json::to_string(&etwevent).unwrap()
    };

    Ok(ret)
}

pub fn dnrrdrsa_to_er(etwevent: cache::templates::DotnetRuntimeRundownRuntimeStartArgs) -> Result<cache::GenericEventRecord, Box<dyn std::error::Error>> {
    
    let mut ret = cache::GenericEventRecord {
        id: None,
        ts: NaiveDateTime::parse_from_str("1970-01-01T00:00:00", "%Y-%m-%dT%H:%M:%S")?,
        ts_type: "etw_ts".to_string(),
        src: "DotnetRuntimeRundownRuntimeStart".to_string(),
        host: "*NA".to_string(),
        context1: "".to_string(),
        context1_attrib: "clr_instance_id".to_string(),
        context2: "".to_string(),
        context2_attrib: "runtime_dll_path".to_string(),
        context3: "*NA".to_string(),
        context3_attrib: "command_line".to_string(),
        rawevent: serde_json::to_string(&etwevent).unwrap()
    };

    ret.context1 = match etwevent.clr_instance_id {
        Some(v) => v.to_string(),
        None => "NA".to_string()
    };

    ret.context2 = match etwevent.runtime_dll_path {
        Some(v) => v.to_string(),
        None => "NA".to_string()
    };

    ret.context3 = match etwevent.command_line {
        Some(v) => v.to_string(),
        None => "NA".to_string()
    };

    
    
        
    ret.ts = match NaiveDateTime::parse_from_str(&etwevent.ts_str, "%Y-%m-%dT%H:%M:%SZ"){
        Ok(v) => v,
        Err(_) => NaiveDateTime::parse_from_str("1970-01-01T00:00:00", "%Y-%m-%dT%H:%M:%S")?
    };
    

    
    
    Ok(ret)
}

