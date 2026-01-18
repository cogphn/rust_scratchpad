use std::sync::atomic::AtomicU32;
use std::sync::atomic::Ordering;
use ferrisetw::parser::Parser;
use ferrisetw::provider::Provider;
use ferrisetw::provider::TraceFlags;
use ferrisetw::schema::Schema;
use ferrisetw::schema_locator::SchemaLocator;
use ferrisetw::trace::UserTrace;
use ferrisetw::EventRecord;
use ferrisetw::provider::EventFilter;
static N_EVENTS: AtomicU32 = AtomicU32::new(0);
use std::sync::Arc;
use wmi::{WMIConnection, Variant};
use ferrisetw::trace::TraceError;
use windows::Win32::System::Threading::{ GetProcessIdOfThread, OpenThread, THREAD_QUERY_LIMITED_INFORMATION };
use std::collections::HashMap;

pub mod templates;
use super::cache;

use std::{sync::atomic::{ AtomicBool }};


pub fn get_hostname() -> String {
    let wmi_con = match WMIConnection::new(){
        Ok(v) => v,
        Err(_) => return "Unknown".to_string()
    };    
    let wmi_computersystem: Vec<HashMap<String, Variant>> = match wmi_con.raw_query("SELECT DNSHostName FROM Win32_ComputerSystem"){
        Ok(v) => v,
        Err(_) => return "Unknown".to_string()
    };

    if let Some(info) = wmi_computersystem.into_iter().next() {
        if let Some(Variant::String(hostname)) = info.get("DNSHostName") {
            return hostname.to_string();
        }
    }
    "Unknown".to_string()
}


fn get_process_by_id(process_id: u32) -> templates::Process {    
    let defaultproc = templates::Process {
        process_id: 0,
        name: "*NA".to_string(),
        executable_path: Some("*NA".to_string()),
        command_line: Some("*NA".to_string()),    
        creation_date: Some("*NA".to_string()),    
        description : Some("*NA".to_string()),    
        handle : Some("*NA".to_string()),
        handle_count: Some(0),
        parent_process_id : Some(0),
        os_name : Some("*NA".to_string()),
        windows_version : Some("*NA".to_string()),
        session_id : Some(0)
    };

    let wmi_con = match WMIConnection::new(){
        Ok(v) => v,
        _ => {
            return defaultproc
        }
    };

    let query = format!(r#"SELECT CreationDate, Name, ProcessId, CommandLine, ParentProcessId, ExecutablePath, 
                        Description, ExecutionState, Handle, HandleCount, InstallDate, OSName, WindowsVersion, SessionId
                         FROM Win32_Process WHERE ProcessId = {}"#
                         , process_id);
    let results: Vec<templates::Process> = match wmi_con.raw_query(&query) {
        Ok(v) => v,
        _ => {
            return defaultproc
        }
    };

    if let Some(process) = results.into_iter().next() {
        process
    } else {
        defaultproc
    }
}

fn get_process_for_tid(tid: u32) -> templates::Process {
    let defaultproc = templates::Process {
        process_id: 0,
        name: "*NA".to_string(),
        executable_path: Some("*NA".to_string()),
        command_line: Some("*NA".to_string()),    
        creation_date: Some("*NA".to_string()),    
        description : Some("*NA".to_string()),    
        handle : Some("*NA".to_string()),
        handle_count: Some(0),
        parent_process_id : Some(0),
        os_name : Some("*NA".to_string()),
        windows_version : Some("*NA".to_string()),
        session_id : Some(0)
    };

    unsafe {
        let thread_handle = match OpenThread(THREAD_QUERY_LIMITED_INFORMATION, false, tid) {
            Ok(v) => v,
            _ => {
                return defaultproc;
            }
        };
        let pid = GetProcessIdOfThread(thread_handle);
        let process: templates::Process = get_process_by_id(pid);
        return process;
    }
}
/*
fn hex_to_ipv4(hex_str: &str) -> Option<String> {
    if hex_str.len() != 16 {
        Some("Invalid arguments");
    }
    let bytes = (0..16)
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex_str[i..i + 2], 16).ok())
        .collect::<Option<Vec<u8>>>()?;
    let ip_addr = format!("{}.{}.{}.{}", bytes[4], bytes[5], bytes[6], bytes[7]);
    Some(ip_addr)
}
*/

/*
fn ms_tcpip_etw_callback(record: &EventRecord, schema_locator: &SchemaLocator) {
    N_EVENTS.fetch_add(1, Ordering::SeqCst);

    match schema_locator.event_schema(record) {
        Err(err) => {
            println!("Unable to get the ETW schema for a TCPIP event: {:?}", err);
        }

        Ok(schema) => {
            parse_etw_tcp_event(&schema, record);
        }
    }
}


fn ms_kernreg_etw_callback(record: &EventRecord, schema_locator: &SchemaLocator) {
    N_EVENTS.fetch_add(1, Ordering::SeqCst);

    match schema_locator.event_schema(record) {
        Err(err) => {
            println!("Unable to get the ETW schema for a Registry event: {:?}", err);
        }

        Ok(schema) => {
            parse_etw_reg_event(&schema, record);
        }
    }
}


fn ms_kernfile_etw_callback (record: &EventRecord, schema_locator: &SchemaLocator) {
    N_EVENTS.fetch_add(1, Ordering::SeqCst);
    match schema_locator.event_schema(record) {
        Err(err) => {
            println!("Unable to get the ETW schema for a File event: {:?}", err);
        }
        Ok(schema) => {
            parse_etw_file_event(&schema, record);
        }
    }

}


fn parse_etw_file_event (schema: &Schema, record: &EventRecord) {
    let parser = Parser::create(record, schema);
    let event_desc = match record.event_id() {      
        // File events   
        26 => "DeletePath",
        28 => "SetLinkPath",
        30 => "CreateNewFile",
        _ => "not_tracked"
    };

    let dtnow = chrono::Utc::now();
    let timestamp = dtnow.to_rfc3339_opts(chrono::format::SecondsFormat::Secs, true);

    let mut noise_event: bool = false;

    let filepath: Option<String> = parser.try_parse("FilePath").ok();
    let filename: Option<String> = parser.try_parse("FileName").ok();

    match filepath  {
        Some(fp) => {
            match fp.find("cache.db-journal") {
                Some(_idx) => {
                    noise_event = true;
                },
                None => {}
            };
        },
        None => {}
    };

    match filename  {
        Some(fp) => {
            match fp.find("cache.db-journal") {
                Some(_idx) => {
                    noise_event = true;
                },
                None => {}
            };
        },
        None => {}
    };
    


    let filevent = templates::GenericFileEvent {
        ts_str: timestamp,
        event_id: record.event_id(),
        event_desc: event_desc.to_string(),
        provider_name: schema.provider_name(),

        irp: parser.try_parse("Irp").ok(),
        thread_id: parser.try_parse("ThreadId").ok(),
        file_object: parser.try_parse("FileObject").ok(),
        file_key: parser.try_parse("FileKey").ok(),
        extra_information: parser.try_parse("ExtraInformation").ok(),
        info_class: parser.try_parse("InfoClass").ok(),
        file_path: parser.try_parse("FilePath").ok(),
        issuing_thread_id: parser.try_parse("IssuingThreadId").ok(),
        create_options: parser.try_parse("CreateOptions").ok(),
        create_attributes: parser.try_parse("CreateAttributes").ok(),
        share_access: parser.try_parse("ShareAccess").ok(),
        file_name: parser.try_parse("FileName").ok()
    };

    if !noise_event {
        println!("{:?}", filevent);
    }
    

}
*/
fn winkernproc_callback(record: &EventRecord, schema_locator: &SchemaLocator) {
    N_EVENTS.fetch_add(1, Ordering::SeqCst);
    match schema_locator.event_schema(record){
        Err(err) => {
            println!("[!] unable to get the ETW schema for a kernel process event: {:?}", err);
        },
        Ok(schema) => {
            parse_kernproc_event(&schema, record);
        }
    }
}


fn parse_kernproc_event(schema: &Schema, record: &EventRecord) {
    let parser = Parser::create(record, schema);
    let provider_name = "Microsoft-Windows-Kernel-Process";
    let event_desc = match record.event_id() {
        5 => "ImageLoad",
        15 => "ProcessRundown",
        _ => "Other"
    };

    let dtnow = chrono::Utc::now();
    let timestamp = dtnow.to_rfc3339_opts(chrono::format::SecondsFormat::Secs, true);

    match record.event_id() {
        5 => {
            let mut kernproc_event = templates::WinKernProcImageLoad {
                ts_str: timestamp,
                event_id: record.event_id(),
                event_desc: event_desc.to_string(),
                provider_name: provider_name.to_string(),

                process_id: parser.try_parse("ProcessID").ok(),
                image_check_sum: parser.try_parse("ImageCheckSum").ok(),
                time_date_stamp: parser.try_parse("TimeDateStamp").ok(),
                image_name: parser.try_parse("ImageName").ok(),
                associated_process: None
            };

            match kernproc_event.process_id {
                Some(v) => {
                    kernproc_event.associated_process = Some(get_process_by_id(v));
                    let evt = serde_json::to_string(&kernproc_event).unwrap();
                    println!("{}", evt);

                    let er: cache::GenericEventRecord = cache::parser::proc_imgload_to_er(kernproc_event).unwrap(); // TODO: FIX
                    
                    cache::get_new_runtime().expect(" [!] could not get cache runtime").spawn( async move {
                        cache::insert_event(&er).await.ok();
                    });          
                    
                    
                },
                _ => {}
            };
            
            

        },
        15 => {
            let kernproc_event = templates::ProcessRundownArgs {
                ts_str: timestamp,
                event_id: record.event_id(),
                event_desc: event_desc.to_string(),
                provider_name: provider_name.to_string(),

                process_id: parser.try_parse("ProcessID").ok(),
                create_time: parser.try_parse("CreateTime").ok(),
                parent_process_id: parser.try_parse("ParentProcessID").ok(),
                session_id: parser.try_parse("SessionID").ok(), 
                flags: parser.try_parse("Flags").ok(),
                image_name: parser.try_parse("ImageName").ok(),
                image_checksum: parser.try_parse("ImageChecksum").ok(),
                time_date_stamp: parser.try_parse("TimeDateStamp").ok(),
                package_full_name: parser.try_parse("PackageFullName").ok(),
                package_relative_app_id: parser.try_parse("PackageRelativeAppID").ok()
            };
            let evt = serde_json::to_string(&kernproc_event).unwrap();
            println!("{}", evt);
        },
        _ => {}
    };
    
}


fn dotnetruntimerundown_callback(record: &EventRecord, schema_locator: &SchemaLocator) {
    N_EVENTS.fetch_add(1, Ordering::SeqCst);
    match schema_locator.event_schema(record){
        Err(err) => {
            println!("[!] unable to get the ETW schema for a dotnet runtime rundown event: {:?}", err);
        },
        Ok(schema) => {
            parse_dotnet_rundown_event(&schema, record);
        }
    }
}

fn parse_dotnet_rundown_event(schema: &Schema, record: &EventRecord) {
    let parser = Parser::create(record, schema);
    let event_desc = match record.event_id() {
        157 => "LoaderAppDomainDCStart",
        158 => "LoaderAppDomainDCStop",
        187 => "RuntimeStart",        
        _ => "Other"
    };

    let dtnow = chrono::Utc::now();
    let timestamp = dtnow.to_rfc3339_opts(chrono::format::SecondsFormat::Secs, true);

    match record.event_id() {
        187 => {
            let dotnetruntimerundownevent_runtimestart = templates::DotnetRuntimeRundownRuntimeStartArgs {
                ts_str: timestamp,
                event_id: record.event_id(),
                event_description: event_desc.to_string(),                
                
                clr_instance_id: parser.try_parse("ClrInstanceID").ok(),
                sku: parser.try_parse("Sku").ok(),
                bcl_major_version: parser.try_parse("BclMajorVersion").ok(),
                bcl_minor_version: parser.try_parse("BclMinorVersion").ok(),
                bcl_build_number: parser.try_parse("BclBuildNumber").ok(),
                bcl_qfe_number: parser.try_parse("BclQfeNumber").ok(),
                vm_major_version: parser.try_parse("VMMajorVersion").ok(),
                vm_minor_version: parser.try_parse("VMMinorVersion").ok(),
                vm_build_number: parser.try_parse("VMQfeNumber").ok(),
                vm_qfe_number: parser.try_parse("VMQfeNumber").ok(),
                startup_flags: parser.try_parse("StartupFlags").ok(),
                startup_mode: parser.try_parse("StartupMode").ok(),
                command_line: parser.try_parse("CommandLine").ok(),
                com_object_guid: parser.try_parse("ComObjectGuid").ok(),
                runtime_dll_path: parser.try_parse("RuntimeDllPath").ok()
            };
            let dotnetstr = serde_json::to_string(&dotnetruntimerundownevent_runtimestart).unwrap();
            println!("{}", dotnetstr);
            
            let er: cache::GenericEventRecord = cache::parser::dnrrdrsa_to_er(dotnetruntimerundownevent_runtimestart).unwrap(); // TODO: FIX

            cache::get_new_runtime().expect(" [!] could not get cache runtime").spawn( async move {
                cache::insert_event(&er).await.ok();
            });
            
            
        },
        _ => {
            let dotnetruntimerundownevent = templates::DotnetRuntimeRundownEvent {
                ts_str: timestamp,
                event_id: record.event_id(),
                event_description: event_desc.to_string(),
                
                app_domain_id: parser.try_parse("AppDomainID").ok(),
                app_domain_flags: parser.try_parse("AppDomainFlags").ok(),
                app_domain_name: parser.try_parse("AppDomainName").ok(),
                app_domain_index: parser.try_parse("AppDomainIndex").ok(),
                clr_instance_id: parser.try_parse("ClrInstanceID").ok()            
            };

            let dotnetstr = serde_json::to_string(&dotnetruntimerundownevent).unwrap();
            println!("{}", dotnetstr);
        }
    } // match

    
}



fn dotnetruntime_callback(record: &EventRecord, schema_locator: &SchemaLocator) {
    N_EVENTS.fetch_add(1, Ordering::SeqCst);
    match schema_locator.event_schema(record){
        Err(err) => {
            println!("[!] unable to get the ETW schema for a dotnet event: {:?}", err);
        },
        Ok(schema) => {
            parse_dotnet_event(&schema, record);
        }
    }
}

fn parse_dotnet_event(schema: &Schema, record: &EventRecord) {
    let parser = Parser::create(record, schema);
    let event_desc = match record.event_id() {
        156 => "LoaderAppDomainLoad",
        83 => "AppDomainResourceManagementMemAllocated",
        85 => "AppDomainResourceManagementThreadCreated",
        87 => "AppDomainResourceManagementDomainEnter",
        _ => "Other"
    };

    let dtnow = chrono::Utc::now();
    let timestamp = dtnow.to_rfc3339_opts(chrono::format::SecondsFormat::Secs, true);

    let mut dotnetevent = templates::DotnetEvent {
        ts_str: timestamp,
        event_id: record.event_id(),
        event_description: event_desc.to_string(),
        app_domain_id: parser.try_parse("AppDomainID").ok(), //156, 83
        assembly_flags: parser.try_parse("AssemblyFlags").ok(),
        app_domain_name: parser.try_parse("AppDomainName").ok(),

        allocated: parser.try_parse("Allocated").ok(),
        clr_instance_id: parser.try_parse("CrlInstanceID").ok(),
        managed_thread_id: parser.try_parse("ManagedThreadID").ok(),
        flags: parser.try_parse("Flags").ok(),
        os_thread_id: parser.try_parse("OSThreadID").ok(),
        associated_process: None
    };

    match dotnetevent.os_thread_id {
        Some(v) => {
            let process = get_process_for_tid(v);
            if process.process_id != 0 {
                dotnetevent.associated_process = Some(process);
            }
        },
        None => { }
    };

    // let dotnetstr = serde_json::to_string(&dotnetevent).unwrap();
    // println!("{}", dotnetstr);

    let er: cache::GenericEventRecord = cache::parser::dng_to_er(dotnetevent).unwrap();
    
    cache::get_new_runtime().expect(" [!] could not get cache runtime").spawn( async move {
        cache::insert_event(&er).await.ok();
    });
}

/*
fn parse_etw_tcp_event(schema: &Schema, record: &EventRecord) {
    let parser = Parser::create(record, schema);
    
    let event_desc = match record.event_id() {        
        1002 => "TcpRequestConnect",
        1017 => "TcpAcceptListenerComplete",
        1033 => "TcpConnectTcbComplete",
        1477 => "TcpConnectionSummary1477",
        _ => "Other",
    };

    let dtnow = chrono::Utc::now();
    let timestamp = dtnow.to_rfc3339_opts(chrono::format::SecondsFormat::Secs, true);

    
    let mut net_event_data = templates::GeneralNetEvent {
        ts_str: timestamp,
        event_id: record.event_id(),
        event_description: event_desc.to_string(),
        provider_name: schema.provider_name(),
        tcb: parser.try_parse("Tcb").ok(), 
        local_address_length: parser.try_parse("LocalAddressLength").ok(),
        local_address: parser.try_parse("LocalAddress").ok(),
        remote_address_length: parser.try_parse("RemoteAddressLength").ok(),
        remote_address: parser.try_parse("RemoteAddress").ok(),
        new_state: parser.try_parse("NewState").ok(),
        rexmit_count: parser.try_parse("RexmitCount").ok(),
        status: parser.try_parse("Status").ok(),
        process_id: parser.try_parse("ProcessId").ok(),
        compartment: parser.try_parse("Compartment").ok(),
        path: parser.try_parse("Path").ok(),
        buffer_size: parser.try_parse("BufferSize").ok(),
        ndk_qp: parser.try_parse("NdkQp").ok(),
        request_context: parser.try_parse("RequestContext").ok(),
        sge_address: parser.try_parse("SgeAddress").ok(),
        sge_length: parser.try_parse("SgeLength").ok(),
        sge_memory_region_token: parser.try_parse("SgeMemoryRegionToken").ok(),
        num_sge: parser.try_parse("NumSge").ok(),
        flags: parser.try_parse("Flags").ok(),
        sge_index: parser.try_parse("SgeIndex").ok(),
        remote_token: parser.try_parse("RemoteToken").ok(),
        state: parser.try_parse("State").ok(),
        pid: parser.try_parse("Pid").ok(),
        request_type: parser.try_parse("RequestType").ok(),
        tcb_or_endpoint: parser.try_parse("TcbOrEndpoint").ok(),
        interface_index: parser.try_parse("InterfaceIndex").ok(),
        address_length: parser.try_parse("AddressLength").ok(),
        remote_port: parser.try_parse("RemotePort").ok(),
        local_port: parser.try_parse("LocalPort").ok(),
        partition_id: parser.try_parse("PartitionId").ok(),
        num_entries: parser.try_parse("NumEntries").ok(),
        name_res_context: parser.try_parse("NameResContext").ok(),
        dns_name: parser.try_parse("DnsName").ok(),
        data_bytes_out: parser.try_parse("DataBytesOut").ok(),
        data_bytes_in: parser.try_parse("DataBytesIn").ok(),
        data_segments_out: parser.try_parse("DataSegmentsOut").ok(),
        data_segments_in: parser.try_parse("DataSegmentsIn").ok(),
        segments_out: parser.try_parse("SegmentsOut").ok(),
        segments_in: parser.try_parse("SegmentsIn").ok(),
        non_recov_da: parser.try_parse("NonRecovDa").ok(),
        non_recov_da_episodes: parser.try_parse("NonRecovDaEpisodes").ok(),
        dup_acks_in: parser.try_parse("DupAcksIn").ok(),
        bytes_retrans: parser.try_parse("BytesRetrans").ok(),
        timeouts: parser.try_parse("Timeouts").ok(),
        spurious_rto_detections: parser.try_parse("SpuriousRtoDetections").ok(),
        fast_retran: parser.try_parse("FastRetran").ok(),
        max_ssthresh: parser.try_parse("MaxSsthresh").ok(),
        max_ss_cwnd: parser.try_parse("MaxSsCwnd").ok(),
        max_ca_cwnd: parser.try_parse("MaxCaCwnd").ok(),
        snd_lim_trans_rwin: parser.try_parse("SndLimTransRwin").ok(),
        snd_lim_time_rwin: parser.try_parse("SndLimTimeRwin").ok(),
        snd_lim_bytes_rwin: parser.try_parse("SndLimBytesRwin").ok(),
        snd_lim_trans_cwnd: parser.try_parse("SndLimTransCwnd").ok(),
        snd_lim_time_cwnd: parser.try_parse("SndLimTimeCwnd").ok(),
        snd_lim_bytes_cwnd: parser.try_parse("SndLimBytesCwnd").ok(),
        snd_lim_trans_snd: parser.try_parse("SndLimTransSnd").ok(),
        snd_lim_time_r_snd: parser.try_parse("SndLimTimeRSnd").ok(),
        snd_lim_bytes_r_snd: parser.try_parse("SndLimBytesRSnd").ok(),
        connection_time_ms: parser.try_parse("ConnectionTimeMs").ok(),
        timestamps_enabled: parser.try_parse("TimestampsEnabled").ok(),
        rtt_us: parser.try_parse("RttUs").ok(),
        min_rtt_us: parser.try_parse("MinRttUs").ok(),
        max_rtt_us: parser.try_parse("MaxRttUs").ok(),
        syn_retrans: parser.try_parse("SynRetrans").ok(),
        congestion_algorithm: parser.try_parse("CongestionAlgorithm").ok(),
        cwnd: parser.try_parse("Cwnd").ok(),
        ss_thresh: parser.try_parse("SSThresh").ok(),
        rcv_wnd: parser.try_parse("RcvWnd").ok(),
        rcv_buf: parser.try_parse("RcvBuf").ok(),
        snd_wnd: parser.try_parse("SndWnd").ok(),
        process_start_key: parser.try_parse("ProcessStartKey").ok(),
        local_address_ipv4: "".to_string(),
        remote_address_ipv4: "".to_string()
    };


    let mut local_address_str = String::new();
    let laddr_length = net_event_data.local_address_length.unwrap_or_default() as usize;
    let mut remote_address_str = String::new();
    let raddr_length = net_event_data.remote_address_length.unwrap_or_default() as usize;

    
    if laddr_length > 15 {
        let local_address_trimmed = &net_event_data.local_address.clone().unwrap_or_default()[0..laddr_length/2].to_vec();
        for byte in &local_address_trimmed.clone() {
            local_address_str.push_str(&format!("{:02x?}", byte)); //
        }
        net_event_data.local_address_ipv4 = hex_to_ipv4(&local_address_str).unwrap_or_default();
    }
    
    if raddr_length > 15 {
        let raddr_trimmed = &net_event_data.remote_address.clone().unwrap_or_default()[0..raddr_length/2].to_vec();
        for byte in &raddr_trimmed.clone() {
            remote_address_str.push_str(&format!("{:02x?}", byte));
        }
        net_event_data.remote_address_ipv4 = hex_to_ipv4(&remote_address_str).unwrap_or_default();
    }
    
    // DBG2
    let netstr = serde_json::to_string(&net_event_data).unwrap();
    println!("{}", netstr);

    
    
    
}


pub fn stop_tcp_event_observer(trace: UserTrace) -> Result<(), TraceError> {
    return trace.stop();
}
*/

// DNS
/*
fn win_dns_etw_callback(record: &EventRecord, schema_locator: &SchemaLocator) {
    N_EVENTS.fetch_add(1, Ordering::SeqCst);

    match schema_locator.event_schema(record) {
        Err(err) => {
            println!("Unable to get the ETW schema for a DNS event: {:?}", err);
        }

        Ok(schema) => {
            parse_dns_event(&schema, record);
        }
    }
}

fn parse_dns_event(schema: &Schema, record: &EventRecord) {
    let parser = Parser::create(record, schema);


    let event_desc = match record.event_id() {      
        // DNS events   
        1001 => "DnsServerForInterface",
        3006 => "task_03006",
        3008 => "task_03008",
        3009 => "task_03009",
        3016 => "task_03016",
        3018 => "task_03018",
        3019 => "task_03019",
        3010 => "task_03010",
        3011 => "task_03011",
        3020 => "task_03020",
        3013 => "task_03013",
        _ => "not_tracked"
    };

    let dtnow = chrono::Utc::now();
    let timestamp = dtnow.to_rfc3339_opts(chrono::format::SecondsFormat::Secs, true);

    let dns_event = templates::GenericDnsEvent {
        event_id: record.event_id(),
        event_desc: event_desc.to_string(),
        ts_str: timestamp,
        provider_name: schema.provider_name(),
        location: parser.try_parse("Location").ok(),
        context: parser.try_parse("Context").ok(),
        interface: parser.try_parse("Interface").ok(),
        total_server_count: parser.try_parse("TotalServerCount").ok(),
        index: parser.try_parse("Index").ok(),
        dynamic_address: parser.try_parse("DynamicAddress").ok(),
        address_length: parser.try_parse("AddressLength").ok(),
        address: parser.try_parse("Address").ok(),
        error_code: parser.try_parse("ErrorCode").ok(),
        dns_suffix: parser.try_parse("DnsSuffix").ok(),
        ad_suffix: parser.try_parse("AdSuffix").ok(),
        query_name: parser.try_parse("QueryName").ok(),
        dns_address_length: parser.try_parse("DnsAddressLength").ok(),
        dns_address: parser.try_parse("DnsAddress").ok(),
        key_name: parser.try_parse("KeyName").ok(),
        dns_sec_validation_required: parser.try_parse("DnsSecValidationRequired").ok(),
        dns_query_over_ip_sec: parser.try_parse("DnsQueryOverIPSec").ok(),
        dns_encryption: parser.try_parse("DnsEncryption").ok(),
        direct_access_server_list: parser.try_parse("DirectAccessServerList").ok(),
        remote_ipsec: parser.try_parse("RemoteIPSEC").ok(),
        remote_encryption: parser.try_parse("RemoteEncryption").ok(),
        proxy_type: parser.try_parse("ProxyType").ok(),
        proxy_name: parser.try_parse("ProxyName").ok(),
        rule_name: parser.try_parse("RuleName").ok(),
        response_question: parser.try_parse("ResponseQuestion").ok(),
        generic_server_list: parser.try_parse("GenericServerList").ok(),
        idn_config: parser.try_parse("IdnConfig").ok(),
        query_type: parser.try_parse("QueryType").ok(),
        query_options: parser.try_parse("QueryOptions").ok(),
        status: parser.try_parse("Status").ok(),
        server_list: parser.try_parse("ServerList").ok(),
        is_network_query: parser.try_parse("IsNetworkQuery").ok(),
        network_query_index: parser.try_parse("NetworkQueryIndex").ok(),
        interface_index: parser.try_parse("InterfaceIndex").ok(),
        is_async_query: parser.try_parse("IsAsyncQuery").ok(),
        query_status: parser.try_parse("QueryStatus").ok(),
        query_results: parser.try_parse("QueryResults").ok(),
        is_parallel_network_query: parser.try_parse("IsParallelNetworkQuery").ok(),
        network_index: parser.try_parse("NetworkIndex").ok(),
        interface_count: parser.try_parse("InterfaceCount").ok(),
        adapter_name: parser.try_parse("AdapterName").ok(),
        local_address: parser.try_parse("LocalAddress").ok(),
        dns_server_address: parser.try_parse("DNSServerAddress").ok(),
        dns_server_ip_address: parser.try_parse("DnsServerIpAddress").ok(),
        response_status: parser.try_parse("ResponseStatus").ok(),
        host_name: parser.try_parse("HostName").ok(),
        adapter_suffix_name: parser.try_parse("AdapterSuffixName").ok(),
        dns_server_list: parser.try_parse("DnsServerList").ok(),
        sent_update_server: parser.try_parse("SentUpdateServer").ok(),
        ipaddress: parser.try_parse("Ipaddress").ok(),
        warning_code: parser.try_parse("WarningCode").ok(),
        next_state: parser.try_parse("NextState").ok(),
        update_reason_code: parser.try_parse("UpdateReasonCode").ok(),
        source_address: parser.try_parse("SourceAddress").ok(),
        source_port: parser.try_parse("SourcePort").ok(),
        destination_address: parser.try_parse("DestinationAddress").ok(),
        destination_port: parser.try_parse("DestinationPort").ok(),
        protocol: parser.try_parse("Protocol").ok(),
        reference_context: parser.try_parse("ReferenceContext").ok(),
        if_guid: parser.try_parse("IfGuid").ok(),
        if_index: parser.try_parse("IfIndex").ok(),
        if_luid: parser.try_parse("IfLuid").ok()
    };

    let dnsstr = serde_json::to_string(&dns_event).unwrap();
    println!("{}", dnsstr);
    
}
*/

/*
fn parse_etw_reg_event(schema: &Schema, record: &EventRecord) {
    let parser = Parser::create(record, schema);
    
    let event_desc = match record.event_id() {      
        // Reg events   
        1 => "task_0CreateKey",
        2 => "task_0OpenKey",
        3 => "task_0DeleteKey",
        4 => "task_0QueryKey",
        5 => "task_0SetValueKey",
        6 => "task_0DeleteValueKey",
        7 => "task_0QueryValueKey",
        _ => "not_tracked"
    };

    let dtnow = chrono::Utc::now();
    let timestamp = dtnow.to_rfc3339_opts(chrono::format::SecondsFormat::Secs, true);

    let reg_event = templates::GenericRegEvent {
		event_id: record.event_id(),
		event_desc: event_desc.to_string(),
        ts_str: timestamp,
		provider_name: schema.provider_name(),

        key_object: parser.try_parse("KeyObject").ok(),
		status: parser.try_parse("Status").ok(),
		etype: parser.try_parse("Type").ok(),
		data_size: parser.try_parse("DataSize").ok(),
		key_name: parser.try_parse("KeyName").ok(),
		value_name: parser.try_parse("ValueName").ok(),
		captured_data_size: parser.try_parse("CapturedDataSize").ok(),
		captured_data: parser.try_parse("CapturedData").ok(),
		previous_data_type: parser.try_parse("PreviousDataType").ok(),
		previous_data_size: parser.try_parse("PreviousDataSize").ok(),
		previous_data_captured_size: parser.try_parse("PreviousDataCapturedSize").ok(),
		previous_data: parser.try_parse("PreviousData").ok(),
		base_object: parser.try_parse("BaseObject").ok(),
		disposition: parser.try_parse("Disposition").ok(),
		base_name: parser.try_parse("BaseName").ok(),
		relative_name: parser.try_parse("RelativeName").ok(),
        bytes_recovered:   parser.try_parse("BytesReceived").ok(),
        entry_count: parser.try_parse("EntryCount").ok(),
        file_size: parser.try_parse("FileSize").ok(),
        flush_flags: parser.try_parse("FlushFlags").ok(),
        hive_file_path: parser.try_parse("HiveFilePath").ok(),
        hive_mount_point: parser.try_parse("HiveMountPoint").ok(),
        index: parser.try_parse("Index").ok(),
        bytes_gathered: parser.try_parse("BytesGathered").ok(),
        bytes_written: parser.try_parse("BytesWritten").ok(),
        flags: parser.try_parse("Flags").ok(),
        info_class: parser.try_parse("InfoClass").ok(),
        source_file: parser.try_parse("SourceFile").ok(),
        source_key_path: parser.try_parse("SourceKeyPath").ok(),
        status_code: parser.try_parse("StatusCode").ok(),
        total_entry_size: parser.try_parse("TotalEntrySize").ok(),
        writes_issued: parser.try_parse("WritesIssued").ok()
    };


    let regevtstr = serde_json::to_string(&reg_event).unwrap();
    println!("{}", regevtstr);
    

}
*/

/*
pub fn start_dns_event_observer() -> Result<UserTrace, TraceError> {

    let win_dns_provider = Provider::by_guid("1c95126e-7eea-49a9-a3fe-a378b03ddb4d") // Microsoft-Windows-DNS-Client
        .add_callback(win_dns_etw_callback)
        .trace_flags(TraceFlags::EVENT_ENABLE_PROPERTY_PROCESS_START_KEY)
        .build();

    let trace = UserTrace::new()
        .enable(win_dns_provider)
        .start_and_process();

    return trace;
}

pub fn stop_dns_event_observer(trace: UserTrace) -> Result<(), TraceError> {
    return trace.stop();
}
*/

pub fn get_trace() -> Result<UserTrace, TraceError> { 

    //let dns_eid_filter = EventFilter::ByEventIds(vec![1001, 3006, 3008, 3009, 3016, 3018, 3019, 3010, 3011, 3020, 3013]);
    //let tcp_eid_filter = EventFilter::ByEventIds(vec![1002]);
    //let reg_eid_filter = EventFilter::ByEventIds(vec![1,3,5,6]);
    //let file_eid_filter = EventFilter::ByEventIds(vec![30, 28, 26]);
    
    let dotnetruntime_filter = EventFilter::ByEventIds(vec![156, 85]);
    let dotnetruntimerundown_filter = EventFilter::ByEventIds(vec![157, 158, 187]);
    let winkernproc_filter = EventFilter::ByEventIds(vec![5, 15]); // 5: ImageLoad , 15: ProcessRundown

    /*
    let win_dns_provider = Provider::by_guid("1c95126e-7eea-49a9-a3fe-a378b03ddb4d") // Microsoft-Windows-DNS-Client
        .add_filter(dns_eid_filter)
        .add_callback(win_dns_etw_callback)
        .trace_flags(TraceFlags::EVENT_ENABLE_PROPERTY_PROCESS_START_KEY)
        .build();

    let ms_tcpip_provider = Provider::by_guid("2F07E2EE-15DB-40F1-90EF-9D7BA282188A") // Microsoft-Windows-TCPIP
        .add_filter(tcp_eid_filter)
        .add_callback(ms_tcpip_etw_callback)
        .trace_flags(TraceFlags::EVENT_ENABLE_PROPERTY_PROCESS_START_KEY)
        //.filter(EventFilter::new(0,0,0)) 
        .build();

    let ms_reg_provider = Provider::by_guid(0x70eb4f03_c1de_4f73_a051_33d13d5413bd) // Microsoft-Windows-Kernel-Registry
        .add_filter(reg_eid_filter)
        .add_callback(ms_kernreg_etw_callback)
        //.trace_flags(TraceFlags::EVENT_ENABLE_PROPERTY_PROCESS_START_KEY)
        .build();

    let win_file_provider = Provider::by_guid(0xedd08927_9cc4_4e65_b970_c2560fb5c289) //Microsoft-Windows-Kernel-File
        .add_callback(ms_kernfile_etw_callback)
        .add_filter(file_eid_filter)
        .build();
    */

    let dotnetruntime_provider = Provider::by_guid(0xe13c0d23_ccbc_4e12_931b_d9cc2eee27e4)
        .add_filter(dotnetruntime_filter)
        .add_callback(dotnetruntime_callback)
        .trace_flags(TraceFlags::EVENT_ENABLE_PROPERTY_PROCESS_START_KEY)
        .build();

    let dotnetruntimerundown_provider = Provider::by_guid(0xa669021c_c450_4609_a035_5af59af4df18)
        .add_filter(dotnetruntimerundown_filter)
        .add_callback(dotnetruntimerundown_callback)
        //.trace_flags(TraceFlags::EVENT_ENABLE_PROPERTY_PROCESS_START_KEY)
        .build();

    let mswinkernproc_provider = Provider::by_guid(0x_22fb2cd6_0e7b_422b_a0c7_2fad1fd0e716)
        .add_filter(winkernproc_filter)
        .add_callback(winkernproc_callback)
        .build();

    let trace = UserTrace::new()
        .enable(dotnetruntime_provider)
        .enable(dotnetruntimerundown_provider)
        .enable(mswinkernproc_provider)
        .start_and_process();

    trace
}


pub fn stop_etw_providers(trace: UserTrace) ->  Result<(), TraceError> {
    return trace.stop();
}

pub fn etw_observer(running: Arc<AtomicBool>) {
    //start_etw_providers

    let trace_ret = get_trace();

    if let Err(e) = &trace_ret {
        eprintln!("[!] Error starting trace: {:?}", e);
        return;
    }
    let trace = trace_ret.unwrap();

    while running.load(Ordering::SeqCst) == true {
        std::thread::sleep(std::time::Duration::new(5, 0)); //wat?
    } 

    let _ = match stop_etw_providers(trace) {
        Ok(_) => {
            println!("[*] Trace stopped successfully");
            return;
        }
        Err (traceerr) => {
            eprintln!("[!] Error stopping trace: {:?}", traceerr);
            return;
        }
    };
}