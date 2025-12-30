use std::sync::Arc;
use std::{thread,sync::atomic::{AtomicBool, Ordering}};
pub mod etwevents;

#[tokio::main]
async fn main() {
    
    println!("[*] starting... ");
    let running: Arc<AtomicBool> = Arc::new(AtomicBool::new(true));
    let rc = running.clone();
    let rc1 = running.clone();

    ctrlc::set_handler(move || {
        running.store(false, Ordering::SeqCst);
        println!("  [*] shutting down...");
    }).expect(" [!] not really sure what kind of error this is :/ ");
    
    let etw_handle = thread::spawn(||{
        etwevents::etw_observer(rc);
    });

    while rc1.load(Ordering::SeqCst) {
        std::thread::sleep(std::time::Duration::from_secs(1));
    }

    let _ = etw_handle.join();
    println!("[.] Done!");
    
}
