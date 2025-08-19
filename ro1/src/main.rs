use windows::{
    core::{Result, HSTRING, PCWSTR},
    Win32::{self, Foundation::HSTR, System::EventLog::*},
};
//use windows::Win32::Foundation::{WIN32_ERROR};
use std::{ffi::c_void, ptr, time::Duration};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

unsafe extern "system" fn event_callback(
    action: EVT_SUBSCRIBE_NOTIFY_ACTION,
    _pcontext: *const c_void,
    hevent: EVT_HANDLE,
) -> u32 {
    match action {
        EvtSubscribeActionDeliver => {
            
            let mut buffer_used = 0;
            let mut property_count = 0;
            let _ = unsafe { 
                EvtRender(
                     Some(EVT_HANDLE(0)),
                     hevent,
                     EvtRenderEventXml.0,
                     0,
                     Some(ptr::null_mut()),
                     &mut buffer_used,
                     &mut property_count,
                 )};
            
            
            let mut buffer = vec![0u8; buffer_used as usize];
            let buffer_size = buffer_used;

            let _ = unsafe {
                 EvtRender(
                     Some(EVT_HANDLE(0)),
                     hevent,
                     EvtRenderEventXml.0,
                     buffer_size,
                     Some(buffer.as_mut_ptr() as *mut c_void),
                     &mut buffer_used,
                     &mut property_count,
                 )
             };
            let xml = String::from_utf8_lossy(&buffer);
            println!("{}", xml);
        }
        _ => {
            println!("Subscription action: {:?}", action);
        }
    }
    0 // Return 0 to indicate success
}

fn get_evt_sub_handle(elog_channel_path:&str, query: &str) -> Result<Win32::System::EventLog::EVT_HANDLE> {
    let channel_path: HSTRING = HSTRING::from(elog_channel_path);
    let q = HSTRING::from(query);

    let elog_sub_handle = unsafe {
        EvtSubscribe(
            None,
            None,
            PCWSTR::from_raw(channel_path.as_ptr()),
            PCWSTR::from_raw(q.as_ptr()),
            None,
            None,
            Some(event_callback),
            EvtSubscribeToFutureEvents.0,
        )
    };

    return elog_sub_handle;
}

#[derive(Debug)]
struct ElogChannel {
    channel_name: String,
    query: String
}

fn main() -> Result<()> {
    
    
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
        println!(" [!] Shutting down...");
    }).expect(" [!] some kind of error presumably.... shutting down");
    
    
    let elog_scope = vec![
        ElogChannel {channel_name: "Application".to_string(), query: "*".to_string()},
        ElogChannel {channel_name: "System".to_string(), query: "*".to_string()},
        ElogChannel {channel_name: "Security".to_string(), query: "*".to_string()}
    ];

    

    println!("[*] Subscribing to Windows Event Logs...");

    let mut sub_handles = Vec::new();
    for c in elog_scope {
        let h = get_evt_sub_handle(&c.channel_name, &c.query);
        if h.clone()?.is_invalid() {
            let sub_err = windows::core::Error::from_win32();
            eprintln!("    [!] failed to subscribe to event {:?} : {:?}", c.channel_name, sub_err);
        }
        sub_handles.push(h);
    }

    /*
    let app_subscription = get_evt_sub_handle("Application", "*");
    if app_subscription.clone()?.is_invalid() {
        let error = windows::core::Error::from_win32();
        eprintln!(" [!] Failed to subscribe to event log: {:?}", error);
        return Err(error);
    }
    // system event log 
    let sys_subscription = get_evt_sub_handle("System", "*");
    if sys_subscription.clone()?.is_invalid() {
        let error = windows::core::Error::from_win32();
        eprintln!(" [!] Failed to subscribe to event log: {:?}", error);
        return Err(error);
    }

    let sec_subscription = get_evt_sub_handle("Security", "*");
    if sec_subscription.clone()?.is_invalid() {
        let error = windows::core::Error::from_win32();
        eprintln!(" [!] Failed to subscribe to event log: {:?}", error);
        return Err(error);
    }
     */
    
    println!("[*] listening for events. Press Ctrl+C to stop.");

    while running.load(Ordering::SeqCst) {
        std::thread::sleep(std::time::Duration::from_secs(1));
    }

    println!("[*] Exiting...");
    unsafe {
        //let _ = EvtClose(app_subscription?);
        //let _ = EvtClose( sys_subscription?);
        //let _ = EvtClose(sec_subscription?);
        for h in sub_handles {
            //println!("    - closing elog handle...");
            let _ = EvtClose(h?);
        }
    } 
    
    Ok(())
}
