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
        6 => "ImageUnload",
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
                    let associated_process = get_process_by_id(v);
                    if associated_process.process_id != 0 {
                        kernproc_event.associated_process = Some(associated_process);
                    }
                    
                    let evt = serde_json::to_string(&kernproc_event).unwrap();
                    if kernproc_event.image_check_sum == Some(0) {
                        println!("{}", evt);
                    }
                    

                    let er: cache::GenericEventRecord = cache::parser::proc_imgload_to_er(kernproc_event).unwrap(); // TODO: FIX
                    
                    cache::get_new_runtime().expect(" [!] could not get cache runtime").spawn( async move {
                        cache::insert_event(&er).await.ok();
                    });          
                    
                    
                },
                _ => {}
            };
            
            

        },
        6 => {
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
                    let associated_process = get_process_by_id(v);
                    if associated_process.process_id != 0 {
                        kernproc_event.associated_process = Some(associated_process);
                    }
                    
                    let evt = serde_json::to_string(&kernproc_event).unwrap();
                    if kernproc_event.image_check_sum == Some(0) {
                        println!("{}", evt);
                    }
                    

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
        151 => "LoaderDomainModuleDCStart",
        157 => "LoaderAppDomainDCStart",
        158 => "LoaderAppDomainDCStop",
        159 => "LoaderThreadDCStop", //has os thread id 
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
        151 => {
            let evt = templates::LoaderDomainModuleDCStartArgs {
                ts_str: timestamp,
                event_id: record.event_id(),
                event_description: event_desc.to_string(),

                module_id: parser.try_parse("ModuleID").ok(),
                assembly_id: parser.try_parse("AssemblyID").ok(),
                app_domain_id: parser.try_parse("AppDomainID").ok(),
                module_flags: parser.try_parse("ModuleFlags").ok(), 
                reserved1: parser.try_parse("Reserved1").ok(),
                module_il_path: parser.try_parse("ModuleILPath").ok(),
                module_native_path: parser.try_parse("ModuleNativePath").ok(),
                clr_instance_id: parser.try_parse("ClrInstanceID").ok()
            };

            let evtstr = serde_json::to_string(&evt).unwrap();
            println!("{}", evtstr);

            let er: cache::GenericEventRecord = cache::parser::ldmdcsa_to_er(evt).unwrap();
            cache::get_new_runtime().expect(" [!] could not get cache runtime").spawn( async move {
                cache::insert_event(&er).await.ok();
            });
        },
        157 => {
            let evt = templates::LoaderAppDomainDCStartArgs {
                ts_str: timestamp,
                event_id: record.event_id(),
                event_description: event_desc.to_string(),

                app_domain_id: parser.try_parse("AppDomainID").ok(),
                app_domain_flags: parser.try_parse("AppDomainFlags").ok(),
                app_domain_name: parser.try_parse("AppDomainName").ok(),
                app_domain_index: parser.try_parse("AppDomainIndex").ok(),
                clr_instance_id: parser.try_parse("ClrInstanceID").ok(),
            };

            let evtstr = serde_json::to_string(&evt).unwrap();
            println!("{}", evtstr);

            let er: cache::GenericEventRecord = cache::parser::laddcsa_to_er(evt).unwrap();
            cache::get_new_runtime().expect(" [!] could not get cache runtime").spawn( async move {
                cache::insert_event(&er).await.ok();
            });

        },
        159 => {
            let mut evt = templates::LoaderThreadDCStopArgs {
                ts_str: timestamp,
                event_id: record.event_id(),
                event_description: event_desc.to_string(),
                
                managed_thread_id: parser.try_parse("ManagedThreadID").ok(),
                app_domain_id: parser.try_parse("AppDomainID").ok(),
                flags: parser.try_parse("Flags").ok(),
                managed_thread_index: parser.try_parse("ManagedThreadIndex").ok(),
                os_thread_id: parser.try_parse("OSThreadID").ok(),
                clr_instance_id: parser.try_parse("ClrInstanceID").ok(),
                associated_process: None
            };

            match evt.os_thread_id {
                Some(v) => {
                    evt.associated_process = Some(get_process_for_tid(v));
                },
                None => {}
            };

            let evtstr = serde_json::to_string(&evt).unwrap();
            println!("{}", evtstr);

            let er: cache::GenericEventRecord = cache::parser::ltdcsa_to_er(evt).unwrap();
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
                clr_instance_id: parser.try_parse("ClrInstanceID").ok(),
                os_thread_id: parser.try_parse("OSThreadID").ok()

            };

            match dotnetruntimerundownevent.os_thread_id {
                Some(v) => {
                    let associated_process = get_process_for_tid(v);
                    println!("[!]{} found associated process for untracked dotnet rundown event (thread id enrichment): {:?}, {:?}", dotnetruntimerundownevent.event_id, associated_process.name, associated_process.command_line);
                },
                None => {}
            };

            let dotnetstr = serde_json::to_string(&dotnetruntimerundownevent).unwrap();
            println!("[!] not written to db: {}", dotnetstr);
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
        151 => "LoaderDomainModuleLoad", // LoaderDomainModuleLoadArgs
        154 => "LoaderAssemblyLoad", // LoaderAssemblyLoadArgs
        _ => "Other"
    };

    let dtnow = chrono::Utc::now();
    let timestamp = dtnow.to_rfc3339_opts(chrono::format::SecondsFormat::Secs, true);
    

    match record.event_id() {
        151 => {
            let evt = templates::LoaderDomainModuleLoadArgs {
                ts_str: timestamp,
                event_id: record.event_id(),
                event_description: event_desc.to_string(),
                
                module_id: parser.try_parse("ModuleID").ok(),
                assembly_id: parser.try_parse("AssemblyID").ok(),
                app_domain_id: parser.try_parse("AppDomainID").ok(),
                module_flags: parser.try_parse("ModuleFlags").ok(), 
                reserved1: parser.try_parse("Reserved1").ok(),
                module_il_path: parser.try_parse("ModuleILPath").ok(),
                module_native_path: parser.try_parse("ModuleNativePath").ok(),
                clr_instance_id: parser.try_parse("ClrInstanceID").ok()
            };
            let json_record =  serde_json::to_string(&evt).unwrap();
            println!("{}", json_record);

            let er: cache::GenericEventRecord = cache::parser::ldmla_to_er(evt).unwrap();
            cache::get_new_runtime().expect(" [!] could not get cache runtime").spawn( async move {
                cache::insert_event(&er).await.ok();
            });
            
            return;
        },
        154 => {
            let evt = templates::LoaderAssemblyLoadArgs {
                ts_str: timestamp,
                event_id: record.event_id(),
                event_description: event_desc.to_string(),

                assembly_id: parser.try_parse("AssemblyID").ok(),
                app_domain_id: parser.try_parse("AppDomainID").ok(),
                assembly_flags: parser.try_parse("AssemblyFlags").ok(),
                fully_qualified_assembly_name: parser.try_parse("FullyQualifiedAssemblyName").ok(),

                binding_id: parser.try_parse("BindingID").ok(),
                clr_instance_id: parser.try_parse("ClrInstanceID").ok()
            };

            let json_record =  serde_json::to_string(&evt).unwrap();
            println!("{}", json_record);
            
            let er: cache::GenericEventRecord = cache::parser::lala_to_er(evt).unwrap();
            cache::get_new_runtime().expect(" [!] could not get cache runtime").spawn( async move {
                cache::insert_event(&er).await.ok();
            });
            
            return;
        },
        // TODO : implement 85 (it has an OS thread id)
        _ => {}
    };

            

    let mut dotnetevent = templates::DotnetEvent {
        ts_str: timestamp,
        event_id: record.event_id(),
        event_description: event_desc.to_string(),
        app_domain_id: parser.try_parse("AppDomainID").ok(), //156, 83
        assembly_flags: parser.try_parse("AssemblyFlags").ok(),
        app_domain_name: parser.try_parse("AppDomainName").ok(),

        allocated: parser.try_parse("Allocated").ok(),
        clr_instance_id: parser.try_parse("CrlInstanceID").ok(),
        managed_thread_id: parser.try_parse("ManagedThreadID").ok(), // TODO: get process for managed thread id 
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
    let er: cache::GenericEventRecord = cache::parser::dng_to_er(dotnetevent).unwrap();
    
    cache::get_new_runtime().expect(" [!] could not get cache runtime").spawn( async move {
        cache::insert_event(&er).await.ok();
    });
}

pub fn get_trace() -> Result<UserTrace, TraceError> { 

    //let dns_eid_filter = EventFilter::ByEventIds(vec![1001, 3006, 3008, 3009, 3016, 3018, 3019, 3010, 3011, 3020, 3013]);
    //let tcp_eid_filter = EventFilter::ByEventIds(vec![1002]);
    //let reg_eid_filter = EventFilter::ByEventIds(vec![1,3,5,6]);
    //let file_eid_filter = EventFilter::ByEventIds(vec![30, 28, 26]);
    
    let dotnetruntime_filter = EventFilter::ByEventIds(vec![154, 156, 85, 87, 151]);
    let dotnetruntimerundown_filter = EventFilter::ByEventIds(vec![157, 158, 159, 187, 151]);
    let winkernproc_filter = EventFilter::ByEventIds(vec![5, 6, 15]); // 5: ImageLoad , 15: ProcessRundown

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