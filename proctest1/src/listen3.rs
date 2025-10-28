use futures::StreamExt;
use tokio::signal;
use tokio::sync::{mpsc, oneshot};

use wmi::{ Variant, WMIConnection, COMLibrary};
use std::process::ExitCode;
use std::collections::HashMap;

use serde::Serialize;
use serde::Deserialize;
use std::thread;

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


fn process_observer(mut stop_rx: mpsc::Receiver<()>, done_tx: oneshot::Sender<()>) -> Result<(), Box<dyn std::error::Error>> {
    let com_lib = match COMLibrary::new(){
        Ok(cl) => cl,
        Err(e) => {
            eprintln!("  [!] failed to initiate com library: {}", e);
            return Err(Box::new(e));
        }
    };

    let wmi_con = match WMIConnection::new(com_lib) {
        Ok(wc) => wc,
        Err(e) => {
            eprintln!("   [!] failed to initiate wmi connection: {}", e);
            return Err(Box::new(e));
        }
    };

    let new_proc_query = "SELECT * FROM Win32_ProcessStartTrace";

    let mut process_start_stream = match wmi_con.async_raw_notification::<HashMap<String, Variant>>(new_proc_query) {
        Ok(stream) => stream,
        Err(e) => {
            eprintln!("    [!] error creating wmi event stream: {}", e);
            return Err(Box::new(e));
        }
    };

    println!("  [*] entering loop...");
    let rt = tokio::runtime::Runtime::new()?;

    rt.block_on(async {

        loop {
            tokio::select! {

                newproc = process_start_stream.next() => {
                    match newproc {
                        Some(Ok(process)) => {
                            println!("{:?}", process);
                        },
                        Some(Err(e)) => {
                            println!(" [!] Error: {:?}", e);
                        },
                        None => {
                            println!(" [!] new process - somehow None");
                        }
                    };
                    
                }

                //_ = signal::ctrl_c() => {
                //    println!("  [*] ctrl+c received... exiting...");
                //    break;
                //}
                _ = stop_rx.recv() => {
                    println!(" [!] stop signal received...exiting");
                    break;
                }
            }  
        }
    });

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

    let _ = stop_tx.send(());

    let _ = procobs_handle.join();

    println!("[.] Done!");

    ExitCode::SUCCESS
}
