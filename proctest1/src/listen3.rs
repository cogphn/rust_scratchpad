use futures::StreamExt;
use tokio::signal;
use tokio::sync::{mpsc, oneshot};

use wmi::{ Variant, WMIConnection, COMLibrary};
use std::process::ExitCode;
use std::collections::HashMap;

use serde::Serialize;
use serde::Deserialize;
use std::thread;

/*
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename = "Win32_Process")] 
#[serde(rename_all = "PascalCase")]
pub struct Process {
    pub process_id: u32,
    pub name: String,
    pub executable_path: Option<String>,
    pub command_line: Option<String>,    
    pub creation_date: Option<String>,    
    pub description : Option<String>,    
    pub handle : Option<String>,
    pub handle_count : Option<u32>,    
    pub parent_process_id : Option<u32>,
    pub os_name : Option<String>,
    pub windows_version : Option<String>,
    pub session_id : Option<u32>
}
 */

fn process_observer(mut stop_rx: mpsc::Receiver<()>, done_tx: oneshot::Sender<()>) -> Result<(), Box<dyn std::error::Error>> {
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

                _ = signal::ctrl_c() => {
                    println!("  [*] ctrl+c received... exiting...");
                    break;
                }
                _ = stop_rx.recv() => {
                    println!(" [!] stop signal received...exiting");
                    break;
                }
            }  
        }
    });
    let _ = done_tx.send(());
    println!("  [*][process_observer] exiting! (gracefully!)");
    Ok(())
}


#[tokio::main]
async fn main() -> ExitCode {

    println!("[*] starting...");

    let (stop_tx, stop_rx) = mpsc::channel(1);
    let (done_tx, done_rx) = oneshot::channel();

    let procobs_handle = thread::spawn(||{
        let _ = process_observer(stop_rx, done_tx);
    });
    println!(" [!][main] running ...");
    let naptime = std::time::Duration::from_secs(10);
    println!("  [*][main] sleeping for a little bit...");
    thread::sleep(naptime);
    println!("  [*][main] sending stop message");
    let _ = stop_tx.send(());
    println!("  [*][main] sent stop message... did it work?");
    procobs_handle.join().unwrap();
    println!("{:?}", done_rx);
    println!("  [*][main] just called join...");
    println!("[.] Done!");

    ExitCode::SUCCESS
}
