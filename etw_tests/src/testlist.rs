use windows::{
    Win32::{
        Foundation::{ERROR_NO_MORE_ITEMS, WIN32_ERROR, GetLastError},
        System::EventLog::{
            EvtClose, EvtNextChannelPath, EvtOpenChannelEnum, EvtRpcLogin, EVT_RPC_LOGIN, EvtOpenSession
        },
    },
};

fn main() -> windows::core::Result<()> {
    unsafe {
        //let login: *const EVT_RPC_LOGIN = std::ptr::null();

        // Open channel enumerator. 
        // From docs: Session: Set to NULL to enumerate the channels on the local computer.
        // flags must be zero lol. "Reserved"
        let h_enum = EvtOpenChannelEnum(None, 0)?; 
        if h_enum.is_invalid() {
            eprintln!("Failed to open channel enumerator");
            return Ok(());
        }

        let mut buffer_size = 256;        
        let mut buffer_used: u32 = 256;
        let mut buffer: Vec<u16> = vec![0u16; 256];
        
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

            buffer.resize(buffer_size as usize, 0);

            match res {
                Ok(v) => {
                    //let err = WIN32_ERROR(windows::Win32::Foundation::GetLastError().0);
                    println!("[DBG] ok returned ...");
                    ///////////////////////// quick unrevised edit 
                    buffer_size = buffer_used;
                    let mut cpb1 = [0u16; 256];

                    match EvtNextChannelPath(
                        h_enum,
                        Some(&mut cpb1),
                        &mut buffer_size
                    ) {
                        Ok(_val) => {
                            println!("[DBG] ok val @ line 60; buffer_size: {:?}", &buffer_size);
                            
                            let channel = String::from_utf16_lossy(
                                &cpb1[..(buffer_size - 1) as usize]
                            );
                            println!("{:?}", channel);
                            
                        },
                        Err(e) => {
                            eprintln!("Failed to read channel path: {}", e);
                        }
                    }
                    // end quick unrevised edit 
                    let err = GetLastError();
                    if err == ERROR_NO_MORE_ITEMS {
                        eprintln!("[!] no more items apparently");
                        break; // No more channels
                    }
                },
                Err(e) => {
                    //let err = WIN32_ERROR(windows::Win32::Foundation::GetLastError().0);
                    let err = GetLastError();
                    eprintln!("{:?}", err.0);

                    if err.0 == 122 { //ERROR_INSUFFICIENT_BUFFER
                        buffer_size = buffer_used;
                        //let channelpathbuffer: Option<&mut [u16]> = Some(&mut [0u16]);
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
                                eprintln!("Failed to read channel path: {}", e);
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
            
        }

        
    } // unsafe

    Ok(())
}



