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

    let service_subkeys_result = RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey(sk_txt);


    let service_subkeys = match service_subkeys_result {
        Err(e) => {
            return Err("[!] Could not open service subkey".into());
        },
        Ok(v) => v
    };
    
    let mut ret: Vec<WinService> = vec![];

    for svc in service_subkeys.enum_keys() {
        match svc {
            Ok(svc_sk) => {
                let service_subkey_txt = sk_txt.to_owned() + "\\" + &svc_sk;
                match hklm.open_subkey(service_subkey_txt) {
                    Err(e) => {
                        println!("[!] Error occured!!: {}", e);
                        continue;
                    },
                    Ok(v) => {
                        let service_subkey = v;
                        let subkey_info = service_subkey.query_info()?;
                        
                        let s: WinService  = WinService {
                            sk_name: svc_sk,
                            display_name: service_subkey.get_value("DisplayName").unwrap_or("".to_string()),
                            error_control: service_subkey.get_value("ErrorControl").unwrap_or(0),
                            image_path: service_subkey.get_value("ImagePath").unwrap_or("".to_string()),
                            owners: service_subkey.get_value("Owners").unwrap_or("".to_string()),
                            start:  service_subkey.get_value("Start").unwrap_or(0),
                            service_type:  service_subkey.get_value("Type").unwrap_or(0),
                            key_last_modified: subkey_info.get_last_write_time_chrono()
                        };
                        ret.push(s);
                        
                    }
                };
            },
            Err(e) => {
                println!("[!] error occured: {}", e);
                continue;
             }
        }
 
 
   }
     
   for r in ret {
    println!("{:?}", r);
   }

    println!("[.] Done!");
    Ok(())
}