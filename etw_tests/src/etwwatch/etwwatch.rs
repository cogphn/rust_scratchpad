use std::sync::Arc;
use std::{thread,sync::atomic::{AtomicBool, Ordering}};
pub mod etwevents;
mod cache;



#[tokio::main]
async fn main() {
    

    let num_initial_rows = cache::initialize_cache("test.db").await.expect(" [!] failed to initialize cache");
    let nir = num_initial_rows;


    println!("[*] starting... ");
    let running: Arc<AtomicBool> = Arc::new(AtomicBool::new(true));
    let rc = running.clone();
    let rc1 = running.clone();
    let rc2 = running.clone();

    ctrlc::set_handler(move || {
        running.store(false, Ordering::SeqCst);
        println!("  [*] shutting down...");
    }).expect(" [!] not really sure what kind of error this is :/ ");
    
    let dbsync_handle = thread::spawn( move||{
        let nir = num_initial_rows;
        let _ = cache::db_disk_sync(rc2, nir);
    });

    let etw_handle = thread::spawn(||{
        etwevents::etw_observer(rc);
    });

    while rc1.load(Ordering::SeqCst) {
        std::thread::sleep(std::time::Duration::from_secs(1));
    }

    let _ = etw_handle.join();
    let _ = dbsync_handle.join();
    let _ = cache::last_write(nir).await;

    println!("[.] Done!");
    
}
