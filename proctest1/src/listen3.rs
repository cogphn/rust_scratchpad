use futures::StreamExt;
use tokio::sync::{mpsc};

use wmi::{ Variant, WMIConnection, COMLibrary};
use std::process::ExitCode;
use std::collections::HashMap;

use std::thread;

#[derive(Debug)]
struct StopSignal;


fn process_observer(mut stop_rx: mpsc::Receiver<StopSignal>) -> Result<(), Box<dyn std::error::Error>> {
    let com_lib = match COMLibrary::new(){
        Ok(cl) => cl,
        Err(e) => {
            eprintln!("  [!][process_observer] failed to initiate com library: {}", e);
            return Err(Box::new(e));
        }
    };

    let wmi_con = match WMIConnection::new(com_lib) {
        Ok(wc) => wc,
        Err(e) => {
            eprintln!("   [!][process_observer] failed to initiate wmi connection: {}", e);
            return Err(Box::new(e));
        }
    };

    let new_proc_query = "SELECT * FROM Win32_ProcessStartTrace";

    let mut process_start_stream = match wmi_con.async_raw_notification::<HashMap<String, Variant>>(new_proc_query) {
        Ok(stream) => stream,
        Err(e) => {
            eprintln!("    [!][process_observer] error creating wmi event stream: {}", e);
            return Err(Box::new(e));
        }
    };

    println!("  [*][process_observer] entering loop...");
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async {

        loop {

            println!("[DBG][process_observer] {:?}", stop_rx);
            tokio::select! {

                newproc = process_start_stream.next() => {
                    match newproc {
                        Some(Ok(process)) => {
                            println!("Process[ {:?} ]", process );
                        },
                        Some(Err(e)) => {
                            println!(" [!] Error: {:?}", e);
                        },
                        None => {
                            println!(" [!] new process - somehow None");
                        }
                    };
                    
                }

                recv =  stop_rx.recv() => {
                    println!(" [!] stop signal received!");
                    break;
                }
            }
        } 
    });
    
    println!("  [*][process_observer] exiting! (gracefully!)");
    Ok(())
}


#[tokio::main]
async fn main() -> ExitCode {

    println!("[*] starting...");

    let (stop_tx, stop_rx) = mpsc::channel::<StopSignal>(1);

    let procobs_handle = thread::spawn(||{
        let _ = process_observer(stop_rx);
    });
    println!(" [!][main] running ...");
    let naptime = std::time::Duration::from_secs(10);
    println!("  [*][main] sleeping for a little bit...");
    thread::sleep(naptime);
    println!("  [*][main] sending stop message");

    let _ = stop_tx.send(StopSignal).await;
    println!("  [*][main] sent stop message... did it work?");
    procobs_handle.join().unwrap();
    println!("  [*][main] just called join...");
    println!("[.] Done!");

    ExitCode::SUCCESS
}
