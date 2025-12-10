use windows::{
    core::{Result},
    Win32::{System::EventLog::*},
};

use std::sync::{atomic::{AtomicBool, Ordering}, mpsc::channel};
use std::sync::Arc;

use argparse::{ArgumentParser, Store};

pub mod wels;



#[tokio::main]
async fn main() -> Result<()> {

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();

    let mut channel_name = "Application".to_string();

    {
        let mut ap = ArgumentParser::new();
        ap.refer(&mut channel_name).add_option(
            &["-c", "--channel-name"],
            Store,
            "WEL Channel Name"
        ).required();
        ap.parse_args_or_exit();
    }


    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);        
        println!(" [*] Shutting down...");
    }).expect(" [!] some kind of error presumably.... shutting down");
    
    let elog_scope = vec![
        wels::ElogChannel { channel_name: channel_name.to_string(), query: "*".to_string() }
    ];
    
    //let elog_scope = wels::get_evt_channels(); // Error: Error { code: HRESULT(0x80070032), message: "The request is not supported." }
        
    println!("  [*] Subscribing to Windows Event Logs...");
    let mut sub_handles = Vec::new();
    for c in elog_scope {
        let h = wels::get_evt_sub_handle(&c.channel_name, &c.query);
        if h.clone()?.is_invalid() {
            let sub_err = windows::core::Error::from_thread(); //ref: https://github.com/microsoft/windows-rs/pull/3701
            eprintln!("    [!] failed to subscribe to event {:?} : {:?}", c.channel_name, sub_err);
        }
        sub_handles.push(h);
    }
    
    
    while running.load(Ordering::SeqCst) {
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    unsafe {        
        for h in sub_handles {
            let _ = EvtClose(h?);
        }
    }

    println!("[.] Done.");
    
    Ok(())
}
