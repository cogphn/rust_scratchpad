use windows::{
    core::{Result, HSTRING, PCWSTR},
    Win32::{self, System::EventLog::*, Foundation::{ERROR_NO_MORE_ITEMS, GetLastError}},
};
use std::{ffi::c_void, ptr};

use super::util;
use super::cache;
use super::parser;

#[derive(Debug)]
pub struct ElogChannel {
    pub channel_name: String,
    pub query: String
}



pub unsafe extern "system" fn event_callback(
    action: EVT_SUBSCRIBE_NOTIFY_ACTION,
    _pcontext: *const c_void,
    hevent: EVT_HANDLE,
) -> u32 {
    match action {
        EvtSubscribeActionDeliver => {
            
            let mut buffer_used = 0;
            let mut property_count = 0;
            let _ = unsafe { 
                EvtRender(
                     Some(EVT_HANDLE(0)),
                     hevent,
                     EvtRenderEventXml.0,
                     0,
                     Some(ptr::null_mut()),
                     &mut buffer_used,
                     &mut property_count,
                 )};
            
            let mut buffer = vec![0u16; buffer_used as usize]; 
            let buffer_size = buffer_used;

            let _ = unsafe {
                 EvtRender(
                     Some(EVT_HANDLE(0)),
                     hevent,
                     EvtRenderEventXml.0,
                     buffer_size,
                     Some(buffer.as_mut_ptr() as *mut c_void),
                     &mut buffer_used,
                     &mut property_count,
                 )
            };

            let xml = String::from_utf16_lossy(&buffer);             
            let jstr = util::evt_xml_to_json(xml);

            let jstr_parsed = parser::wel_json_to_er(&jstr.as_ref().unwrap_or(&"".to_string()));
            if let Ok(er) = jstr_parsed {                
                //println!("{:?}", er); // DEBUG
                cache::get_new_runtime().expect("[!] cannot get cache runtime").spawn(async move {
                    cache::insert_event(&er).await.ok();
                });
                

            } else {
                eprintln!("ERROR:  {:?}", jstr_parsed.err());
            }
        }
        _ => {
            println!("Subscription action: {:?}", action);
        }
    }
    0 // 0 = success
}



pub fn get_evt_sub_handle(elog_channel_path:&str, query: &str) -> Result<Win32::System::EventLog::EVT_HANDLE> {
    let channel_path: HSTRING = HSTRING::from(elog_channel_path);
    let q = HSTRING::from(query);

    let elog_sub_handle = unsafe {
        EvtSubscribe(
            None,
            None,
            PCWSTR::from_raw(channel_path.as_ptr()),
            PCWSTR::from_raw(q.as_ptr()),
            None,
            None,
            Some(event_callback),
            EvtSubscribeToFutureEvents.0,
        )
    };

    return elog_sub_handle;
}

// TODO: implement
fn get_evt_channels() -> Vec<ElogChannel> {
    let mut ret: Vec<ElogChannel> = Vec::new();
    unsafe {
        let h_enum = match EvtOpenChannelEnum(None, 0) {
            Ok(v) => v,
            Err(_) => {
                eprintln!(" [!][wels::get_evt_channels] error calling EvtOpenChannelEnum");
                return ret;
            }
        }; 
        if h_enum.is_invalid() {
            eprintln!(" [!][wels::get_evt_channels] Failed to open channel enumerator");
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
                            ret.push(ElogChannel{
                                channel_name: channel.to_string(), query: "*".to_string()
                            });
                            
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
                                ret.push(ElogChannel{
                                    channel_name: channel.to_string(), query: "*".to_string()
                                });
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