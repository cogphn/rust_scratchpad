use std::io;
use std::path::Path;
use winreg::enums::*;
use winreg::RegKey;
use chrono::NaiveDateTime;


#[derive(Debug)]
struct WinService {
    sk_name: String,
    display_name: String, 
    error_control: String, 
    image_path: String,
    owners: String, 
    start: String,
    service_type: String,
    key_last_modified: NaiveDateTime
}

fn main()  -> Result<(), Box<dyn std::error::Error>>  {
    println!("[*] starting...");
    
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let sk_txt = "SYSTEM\\CurrentControlSet\\Services";

    for svc in RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey(sk_txt)?
        .enum_keys().map(|x| x.unwrap())
        {
            println!("[DBG]: {}", svc);
            let service_subkey_text = sk_txt.to_owned() + "\\" + &svc;
            
            match hklm.open_subkey(service_subkey_text) {
                Err(e) => {
                    println!("[!] Error occured!!: {}", e);
                    continue;
                },
                Ok(v) => {
                    let service_subkey = v;
                    let subkey_info = service_subkey.query_info()?;
                    
                    let s: WinService  = WinService {
                        sk_name: svc,
                        display_name: service_subkey.get_value("DisplayName").unwrap_or("".to_string()),
                        error_control: service_subkey.get_value("ErrorControl").unwrap_or("".to_string()),
                        image_path: service_subkey.get_value("ImagePath").unwrap_or("".to_string()),
                        owners: service_subkey.get_value("Owners").unwrap_or("".to_string()),
                        start:  service_subkey.get_value("Start").unwrap_or("".to_string()),
                        service_type:  service_subkey.get_value("Type").unwrap_or("".to_string()),
                        key_last_modified: subkey_info.get_last_write_time_chrono()
                    };
                    

                    println!("{:?}, {:?}", subkey_info, s);
                }
            };


        }
    
    
    /*
    let info = cur_ver.query_info()?;
    println!("info = {:?}", info);
    let mt = info.get_last_write_time_system();
    println!(
        "last_write_time as windows_sys::Win32::Foundation::SYSTEMTIME = {}-{:02}-{:02} {:02}:{:02}:{:02}",
        mt.wYear, mt.wMonth, mt.wDay, mt.wHour, mt.wMinute, mt.wSecond
    );
    */


    // enable `chrono` feature on `winreg` to make this work
    // println!(
    //     "last_write_time as chrono::NaiveDateTime = {}",
    //     info.get_last_write_time_chrono()
    // );


    println!("[.] Done!");
    Ok(())
}