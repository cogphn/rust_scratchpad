use windows::{
    core::{Result},
    Win32::{System::EventLog::*},
};

use std::{sync::atomic::{AtomicBool, Ordering}};
use std::sync::Arc;
use std::thread;
use tokio::sync::{mpsc};

use crate::rtevents::StopSignal;

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
    let rc_etwevents = running.clone();
    let rc_dbsync = running.clone();
    let (stop_tx, stop_rx) = mpsc::channel::<rtevents::StopSignal>(1);


    let num_initial_rows = cache::initialize_cache("cache.db").await.expect(" [!] failed to initialize cache");
    let nir = num_initial_rows;


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
        
    println!("  [*] Subscribing to Windows Event Logs...");
    let mut sub_handles = Vec::new();
    for c in elog_scope {
        let h = wels::get_evt_sub_handle(&c.channel_name, &c.query);
        if h.clone()?.is_invalid() {
            let sub_err = windows::core::Error::from_win32();
            eprintln!("    [!] failed to subscribe to event {:?} : {:?}", c.channel_name, sub_err);
        }
        sub_handles.push(h);
    }
    println!("  [*] collecting volatile data (netconns)...");
    let _ = rtevents::write_netconns_to_cache().await;
    println!("  [*] collecting volatile data (processlist)...");
    let _ = rtevents::write_proclist_to_cache().await;
    println!("  [*] dumping windows services...");
    let _ = rtevents::write_services_to_cache().await;

    // ETW listener startup    
    let etw_handle = thread::spawn(||{
        rtevents::etw_observer(rc_etwevents);
    });

    // DBsync start
    println!("[DBG - main] initial rows: {}", num_initial_rows);
    let dbsync_handle = thread::spawn( move||{
        let nir = num_initial_rows;
        let _ = cache::db_disk_sync(rc_dbsync, nir);
    });

    //process observer 
    let procobs_handle = thread::spawn(||{
        let _ = rtevents::process_observer(stop_rx);
    });
    
    // process observer 
    println!("\n");
    println!("[*] Running! Now listening for events; press ctrl+c to exit");
    println!("\n");
    
    
    while running.load(Ordering::SeqCst) {
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    let _ = stop_tx.send(StopSignal).await;
    unsafe {        
        for h in sub_handles {
            let _ = EvtClose(h?);
        }
        let _ = etw_handle.join();
        let _ = dbsync_handle.join();
        let _ = procobs_handle.join();
    }

    let _  = cache::last_write(nir).await;

    println!("[.] Done.");
    
    Ok(())
}
