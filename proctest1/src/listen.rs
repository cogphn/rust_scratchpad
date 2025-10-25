use futures::StreamExt;
//use std::collections::HashMap;
use tokio::signal;
use wmi::{ Variant, WMIConnection, COMLibrary};
use std::process::ExitCode;
use std::collections::HashMap;




#[tokio::main]
async fn main() -> ExitCode {

    println!("[*] starting...");

    let com_lib = match COMLibrary::new(){
        Ok(cl) => cl,
        Err(e) => {
            eprintln!("  [!] failed to initiate com library: {}", e);
            return ExitCode::FAILURE;
        }
    };

    let wmi_con = match WMIConnection::new(com_lib) {
        Ok(wc) => wc,
        Err(e) => {
            eprintln!("   [!] failed to initiate wmi connection: {}", e);
            return ExitCode::FAILURE;
        }
    };

    let new_proc_query = "SELECT * FROM Win32_ProcessStartTrace";

    let mut process_start_stream = match wmi_con.async_raw_notification::<HashMap<String, Variant>>(new_proc_query) {
        Ok(stream) => stream,
        Err(e) => {
            eprintln!("    [!] error creating wmi event stream: {}", e);
            return ExitCode::FAILURE;
        }
    };

    let cc = tokio::signal::ctrl_c();
    println!("  [*] entering loop...");

    loop {
        tokio::select! {

            newproc = process_start_stream.next() => {
                match newproc {
                    Some(Ok(event)) => {
                        for (key, value) in event {
                            match value {
                                Variant::String(s) => println!(" {}: {}", key, s),
                                _ => println!("{}:  {:?}", key, value)
                            };
                        }
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
        }    
    }


    println!("[.] Done!");

    ExitCode::SUCCESS
}
