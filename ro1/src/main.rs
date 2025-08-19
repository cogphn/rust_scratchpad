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
            println!("Event XML: {}", xml);
        }
        _ => {
            // Handle other actions like EvtSubscribeActionError
            println!("Subscription action: {:?}", action);
        }
    }
    0 // Return 0 to indicate success
}

fn get_evt_handle(elog_channel_path:&str) -> Result<Win32::System::EventLog::EVT_HANDLE> {
    let channel_path: HSTRING = HSTRING::from(elog_channel_path);

    let elog_sub_handle = unsafe {
        EvtSubscribe(
            None,
            None,
            PCWSTR::from_raw(channel_path.as_ptr()),
            PCWSTR::from_raw(HSTRING::from("*").as_ptr()),
            None,
            None,
            Some(event_callback),
            EvtSubscribeToFutureEvents.0,
        )
    };

    return elog_sub_handle;
}

fn main() -> Result<()> {
    
    
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
        println!("Ctrl+C received, shutting down...");
    }).expect(" [!] some kind of error presumably.... shutting down");
    
    //let application_channel_path = HSTRING::from("Application");
    let system_channel_path = HSTRING::from("System");    
    
    let query = HSTRING::from("*");
    

    println!("[*] Subscribing to Windows Event Log...");

    // application eventlog 
    /*
    let app_subscription = unsafe {
        EvtSubscribe(
            None,
            None,
            PCWSTR::from_raw(application_channel_path.as_ptr()),
            PCWSTR::from_raw(query.as_ptr()),
            None,
            None,
            Some(event_callback),
            //EvtSubscribeStartAtOldestRecord.0,
            EvtSubscribeToFutureEvents.0,
        )
    };
     */
    let app_subscription = get_evt_handle("Application");


    if app_subscription.clone()?.is_invalid() {
        let error = windows::core::Error::from_win32();
        eprintln!(" [!] Failed to subscribe to event log: {:?}", error);
        return Err(error);
    }

    // system event log 
    let sys_subscription = unsafe {
        EvtSubscribe(
            None,
            None,
            PCWSTR::from_raw(system_channel_path.as_ptr()),
            PCWSTR::from_raw(query.as_ptr()),
            None,
            None,
            Some(event_callback),            
            EvtSubscribeToFutureEvents.0,
        )
    };

    if sys_subscription.clone()?.is_invalid() {
        let error = windows::core::Error::from_win32();
        eprintln!(" [!] Failed to subscribe to event log: {:?}", error);
        return Err(error);
    }
    

    
    
    println!("[*] listening for events. Press Ctrl+C to stop.");
    
    /*
    loop {
        std::thread::sleep(std::time::Duration::from_secs(1));
    } */

    while running.load(Ordering::SeqCst) {
        std::thread::sleep(std::time::Duration::from_secs(1));
    }

    //#[allow(unreachable_code)]
    // TODO: fix
    println!("[*] Exiting...");
    unsafe {
        let _ = EvtClose(app_subscription?);
        let _ = EvtClose( sys_subscription?);
    } 
    
    Ok(())
}
