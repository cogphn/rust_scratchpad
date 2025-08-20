use windows::{
    core::{Result, HSTRING, PCWSTR},
    Win32::{self, Foundation::HSTR, System::EventLog::*},
};
//use windows::Win32::Foundation::{WIN32_ERROR};
use std::{ffi::c_void, ptr, time::Duration};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

pub mod rtevents;
pub mod wels;

pub mod util;



fn main() -> Result<()> {
    
    

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
        println!(" [*] Shutting down...");
    }).expect(" [!] some kind of error presumably.... shutting down");
    
    // TODO: read from config file
    let elog_scope = vec![
        wels::ElogChannel {channel_name: "Application".to_string(), query: "*".to_string()},
        wels::ElogChannel {channel_name: "System".to_string(), query: "*".to_string()},
        wels::ElogChannel {channel_name: "Security".to_string(), query: "*".to_string()}
    ];

    println!("[*] Subscribing to Windows Event Logs...");

    let mut sub_handles = Vec::new();
    for c in elog_scope {
        let h = wels::get_evt_sub_handle(&c.channel_name, &c.query);
        if h.clone()?.is_invalid() {
            let sub_err = windows::core::Error::from_win32();
            eprintln!("    [!] failed to subscribe to event {:?} : {:?}", c.channel_name, sub_err);
        }
        sub_handles.push(h);
    }


    println!("[*] listening for events. Press Ctrl+C to stop.");

    while running.load(Ordering::SeqCst) {
        std::thread::sleep(std::time::Duration::from_secs(1));
    }

    println!("[*] Exiting...");
    unsafe {        
        for h in sub_handles {
            let _ = EvtClose(h?);
        }
    } 

    println!("[.] Done.");
    
    Ok(())
}
