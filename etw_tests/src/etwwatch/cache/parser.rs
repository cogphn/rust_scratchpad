use chrono::{ NaiveDateTime }; 
use crate::cache;

/*
pub fn get_default_date() -> NaiveDateTime {
    let dd = NaiveDate::from_ymd_opt(1970, 01, 01).unwrap();
    let dt = NaiveTime::from_hms_opt(0, 0, 0).unwrap();
    return NaiveDateTime::new(dd, dt);
}
    */

pub fn proc_imgload_to_er(kernproc_event: cache::templates::WinKernProcImageLoad) -> Result<cache::GenericEventRecord, Box<dyn std::error::Error>> {

    let mut ret = cache::GenericEventRecord {
        id: None,
        ts: NaiveDateTime::parse_from_str("1970-01-01T00:00:00", "%Y-%m-%dT%H:%M:%S")?,
        ts_type: "timestamp".to_string(),
        src: "proc_image_load".to_string(),
        host: "*NA".to_string(),
        filename: "NA".to_string(),
        context1: "5".to_string(),
        context1_attrib: "event_id".to_string(),
        context2: "NA".to_string(),
        context2_attrib: "image_name".to_string(),
        context3: "*NA".to_string(),
        context3_attrib: "process_id".to_string(),
        rawevent: serde_json::to_string(&kernproc_event).unwrap()
    };

    ret.ts = match NaiveDateTime::parse_from_str(&kernproc_event.ts_str, "%Y-%m-%dT%H:%M:%SZ"){
        Ok(v) => v,
        Err(_) => NaiveDateTime::parse_from_str("1970-01-01T00:00:00", "%Y-%m-%dT%H:%M:%S")?
    };

    match kernproc_event.image_name {
        Some(v) => {
            ret.context2 = v.to_string();
            ret.filename = v.to_string();
        },
        None => {}
    };
    /*
    ret.context2 = match kernproc_event.image_name {
        Some(v) => v.to_string(),
        None => "NA".to_string()
    };
    */

    ret.context3 = match kernproc_event.process_id {
        Some(v) => v.to_string(),
        None => "NA".to_string()
    };

    Ok(ret)
    
}

pub fn dng_to_er(etwevent: cache::templates::DotnetEvent) -> Result<cache::GenericEventRecord, Box<dyn std::error::Error>> { //dotnet generic struct to generic event record

    let mut ret = cache::GenericEventRecord {
        id: None,
        ts: NaiveDateTime::parse_from_str("1970-01-01T00:00:00", "%Y-%m-%dT%H:%M:%S")?,
        ts_type: "etw_ts".to_string(),
        src: "dotnet_generic".to_string(),
        host: "*NA".to_string(),
        filename: "NA".to_string(),
        context1: "NA".to_string(),
        context1_attrib: "event_id".to_string(),
        context2: "NA".to_string(),
        context2_attrib: "app_domain_name".to_string(),
        context3: "*NA".to_string(),
        context3_attrib: "app_domain_id".to_string(),
        rawevent: serde_json::to_string(&etwevent).unwrap()
    };


    ret.context1 = etwevent.event_id.to_string(); 

    ret.context2 = match etwevent.app_domain_name {
        Some(v) => v.to_string(),
        None => "NA".to_string()
    };

    ret.context3 = match etwevent.app_domain_id {
        Some(v) => v.to_string(),
        None => "NA".to_string()
    };

    ret.ts = match NaiveDateTime::parse_from_str(&etwevent.ts_str, "%Y-%m-%dT%H:%M:%SZ"){
        Ok(v) => v,
        Err(_) => NaiveDateTime::parse_from_str("1970-01-01T00:00:00", "%Y-%m-%dT%H:%M:%S")?
    };

    match etwevent.associated_process {
        Some(proc) => {
            match proc.executable_path {
                Some(v) => ret.filename = v,
                _ => {}
            };
        },
        None => {}
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
        filename: "NA".to_string(),
        context1: "".to_string(),
        context1_attrib: "event_id".to_string(),
        context2: "".to_string(),
        context2_attrib: "runtime_dll_path".to_string(),
        context3: "*NA".to_string(),
        context3_attrib: "command_line".to_string(),
        rawevent: serde_json::to_string(&etwevent).unwrap()
    };

    ret.context1 = etwevent.event_id.to_string();
    

    match etwevent.runtime_dll_path {
        Some(v) => {
            ret.context2 = v.to_string();
            ret.filename = v.to_string();
        },
        None => {}
    }

    ret.context3 = match etwevent.command_line {
        Some(v) => v.to_string(),
        None => "NA".to_string()
    };

    /*
    ret.filename = match etwevent.runtime_dll_path {
        Some(v) => v.to_string(),
        None => "NA".to_string()
    };
    */
        
    ret.ts = match NaiveDateTime::parse_from_str(&etwevent.ts_str, "%Y-%m-%dT%H:%M:%SZ"){
        Ok(v) => v,
        Err(_) => NaiveDateTime::parse_from_str("1970-01-01T00:00:00", "%Y-%m-%dT%H:%M:%S")?
    };
    

    
    
    Ok(ret)
}

