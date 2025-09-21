use windows::{
    core::{Result},
    Win32::{System::EventLog::*},
};

//use std::{rc, sync::atomic::{AtomicBool, Ordering}};
use std::{sync::atomic::{AtomicBool, Ordering}};
use std::sync::Arc;
use std::thread;
pub mod rtevents;
pub mod wels;

pub mod util;
pub mod cache;
pub mod parser;

pub mod snapshot;


#[tokio::main]
async fn main() -> Result<()> {
    

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    let rc_rtevents = running.clone();
    let rc_etwevents = running.clone();

    cache::initialize_cache("cache.db").await.expect(" [!] failed to initialize cache");

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
    
    println!("[*] collecting volatile data (processlist)...");
    let _ = rtevents::write_proclist_to_cache().await;
    

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
    
    let etw_handle = thread::spawn(||{
        rtevents::etw_observer(rc_etwevents);
    });
    

    let _ = rtevents::process_observer(rc_rtevents).await;

    while running.load(Ordering::SeqCst) {
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    
    unsafe {        
        for h in sub_handles {
            let _ = EvtClose(h?);
        }
        let _ = etw_handle.join();
    }

    println!("[.] Done.");
    
    Ok(())
}
