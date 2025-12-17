use windows::{
    Win32::{
        Foundation::{ERROR_NO_MORE_ITEMS, GetLastError},
        System::EventLog::{
            EvtNextChannelPath, EvtOpenChannelEnum
        },
    },
};


fn get_evt_Channels() -> Vec<String> {
    let mut ret: Vec<String> = Vec::new();
    unsafe {
        let h_enum = match EvtOpenChannelEnum(None, 0) {
            Ok(v) => v,
            Err(_) => {
                eprintln!(" [!] error calling EvtOpenChannelEnum");
                return ret;
            }
        }; 
        if h_enum.is_invalid() {
            eprintln!(" [!] Failed to open channel enumerator");            
            return ret;
        }
        let mut buffer_used: u32 = 256;
        loop {
            let mut pathbuffer = [0u16; 256];
            
            let res = EvtNextChannelPath(
                h_enum,
                Some(&mut pathbuffer),
                &mut buffer_used,
            );

            match res {
                Ok(_v) => {
                    let mut cpb1 = [0u16; 256];

                    match EvtNextChannelPath(
                        h_enum,
                        Some(&mut cpb1),
                        &mut buffer_used
                    ) {
                        Ok(_val) => {
                            let channel = String::from_utf16_lossy(
                                &cpb1[..(buffer_used - 1) as usize]
                            );                            
                            ret.push(channel);
                            
                        },
                        Err(e) => {
                            eprintln!("Failed to read channel path: {}", e);
                        }
                    }
                    let err = GetLastError();
                    if err == ERROR_NO_MORE_ITEMS {
                        eprintln!("[!] no more items apparently");
                        break; // No more channels
                    }
                },
                Err(_e) => {
                    let err = GetLastError();

                    if err.0 == 122 { //ERROR_INSUFFICIENT_BUFFER
                        let mut channelpathbuffer = [0u16; 256];
                        match EvtNextChannelPath(
                            h_enum,
                            Some(&mut channelpathbuffer),
                            &mut buffer_used    
                        ) {
                            Ok(_val) => {
                                let channel = String::from_utf16_lossy(
                                    &channelpathbuffer[..(buffer_used as usize - 1)],
                                );
                                println!("{}", channel);
                            },
                            Err(e) => {
                                eprintln!(" [!] Failed to read channel path: {}", e);
                            }
                        }
                    } else if err.0 == 259  {
                        eprintln!("[!][ERR][ERROR_NO_MORE_ITEMS]{:?}", err);
                        break;
                    } else {
                        eprintln!("[!][ERR] {:?}", err);
                        break;
                    }
                }
            } // match

        } // evt channel loop
        
    }
    return ret;
}

fn main() -> windows::core::Result<()> {
    unsafe {
        let h_enum = EvtOpenChannelEnum(None, 0)?; 
        if h_enum.is_invalid() {
            eprintln!("Failed to open channel enumerator");
            return Ok(());
        }
        let mut buffer_used: u32 = 256;        
        println!("[DBG] entering loop");

        
        loop {
            // First call to get required buffer size            
            //let mut pathbuffer: Option<&mut [u16]> = Some(&mut [0u16; 256]);
            let mut pathbuffer = [0u16; 256];
            
            let res = EvtNextChannelPath(
                h_enum,
                Some(&mut pathbuffer),
                &mut buffer_used,
            );
            match res {
                Ok(_v) => {
                    let mut cpb1 = [0u16; 256];

                    match EvtNextChannelPath(
                        h_enum,
                        Some(&mut cpb1),
                        &mut buffer_used
                    ) {
                        Ok(_val) => {
                            let channel = String::from_utf16_lossy(
                                &cpb1[..(buffer_used - 1) as usize]
                            );
                            println!("{}", channel);
                            
                        },
                        Err(e) => {
                            eprintln!("Failed to read channel path: {}", e);
                        }
                    }
                    let err = GetLastError();
                    if err == ERROR_NO_MORE_ITEMS {
                        eprintln!("[!] no more items apparently");
                        break; // No more channels
                    }
                },
                Err(_e) => {
                    let err = GetLastError();

                    if err.0 == 122 { //ERROR_INSUFFICIENT_BUFFER
                        let mut channelpathbuffer = [0u16; 256];
                        match EvtNextChannelPath(
                            h_enum,
                            Some(&mut channelpathbuffer),
                            &mut buffer_used    
                        ) {
                            Ok(_val) => {
                                let channel = String::from_utf16_lossy(
                                    &channelpathbuffer[..(buffer_used as usize - 1)],
                                );
                                println!("{}", channel);
                            },
                            Err(e) => {
                                eprintln!(" [!] Failed to read channel path: {}", e);
                            }
                        }
                    } else if err.0 == 259  {
                        eprintln!("[!][ERR][ERROR_NO_MORE_ITEMS]{:?}", err);
                        return Ok(())
                    } else {
                        eprintln!("[!][ERR] {:?}", err);
                        return Ok(())
                    }
                }
            }
            
        } // loop
    } // unsafe

    Ok(())
}



