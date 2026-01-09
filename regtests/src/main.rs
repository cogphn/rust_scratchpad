//use std::io;
//use std::path::Path;
use winreg::enums::*;
use winreg::RegKey;
use chrono::NaiveDateTime;


#[derive(Debug)]
struct WinService {
    sk_name: String,
    display_name: String, 
    error_control: u32, 
    image_path: String,
    owners: String, 
    start: u32,
    service_type: u32,
    key_last_modified: NaiveDateTime
}

fn main()  -> Result<(), Box<dyn std::error::Error>>  {
    println!("[*] starting...");
    
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let sk_txt = "SYSTEM\\CurrentControlSet\\Services";

    for svc in RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey(sk_txt)?
        .enum_keys().map(|x| x.unwrap())
        {
            //println!("[DBG]: {}", svc);
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
                        error_control: service_subkey.get_value("ErrorControl").unwrap_or(0),
                        image_path: service_subkey.get_value("ImagePath").unwrap_or("".to_string()),
                        owners: service_subkey.get_value("Owners").unwrap_or("".to_string()),
                        start:  service_subkey.get_value("Start").unwrap_or(0),
                        service_type:  service_subkey.get_value("Type").unwrap_or(0),
                        key_last_modified: subkey_info.get_last_write_time_chrono()
                    };

                    if s.image_path != "" {
                        println!("{:?},\n{:?}", subkey_info, s);
                        //println!("{:?}",s.start);
                    }
                    
                    
                }
            };


        }
    

    println!("[.] Done!");
    Ok(())
}