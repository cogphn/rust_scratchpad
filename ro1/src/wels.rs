use windows::{
    core::{Result, HSTRING, PCWSTR},
    Win32::{self, System::EventLog::*},
};
use std::{ffi::c_void, ptr};
//use tokio;

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
            
            let mut buffer = vec![0u16; buffer_used as usize]; // work
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

            let xml = String::from_utf16_lossy(&buffer); // works            
            let jstr = util::evt_xml_to_json(xml);

            let jstr_parsed = parser::wel_json_to_er(&jstr.as_ref().unwrap_or(&"".to_string()));
            if let Ok(er) = jstr_parsed {                
                println!("{:?}", er); // DEBUG
                cache::get_runtime().spawn(async move {
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
    0 // Return 0 to indicate success
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
