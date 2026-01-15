// NOT WORKING
/*
[*] starting...
  [*] thread id: 23148
  [*] getting thread handle...
Error: Error { code: HRESULT(0x80070057), message: "The parameter is incorrect." }
*/


use windows::Win32::System::Threading::{GetProcessIdOfThread, OpenThread, THREAD_ACCESS_RIGHTS };
use argparse::ArgumentParser;
use argparse::Store;

fn main() -> Result<(), Box <dyn std::error::Error>>{
    println!("[*] starting...");

    let mut thread_id = 0;
    {
        let mut ap = ArgumentParser::new();
        ap.set_description("Process lookup");
        ap.refer(&mut thread_id)
            .add_option(&["-t","--tid"], 
            Store,
            "thread id"
        ).required();
       
        ap.parse_args_or_exit();
    }

    
    if thread_id != 0 {
        println!("  [*] thread id: {}", thread_id);

        unsafe {

            // TODO: get thread handle
            println!("  [*] getting thread handle...");
            let desired_access = THREAD_ACCESS_RIGHTS(64);
            let thread_handle = OpenThread( desired_access, false, thread_id)?;

            println!("  [*] getting process id...");
            //let process_id = GetProcessIdOfThread(thread_id);
            let process_id = GetProcessIdOfThread(thread_handle);
            println!("PID: {}", process_id);
        }
        
        
    }


    println!("[.] Done!");

    Ok(())

}
