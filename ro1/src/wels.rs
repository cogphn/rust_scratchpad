use windows::{
    core::{Result, HSTRING, PCWSTR},
    Win32::{self, Foundation::HSTR, System::EventLog::*},
};
//use windows::Win32::Foundation::{WIN32_ERROR};
use std::{ffi::c_void, ptr, string::FromUtf8Error, time::Duration};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use super::util;

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
            
            
            //let mut buffer = vec![0u8; buffer_used as usize]; //working - old 
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
            //let xml = String::from_utf8_lossy(&buffer); //working - old 
            let xml = String::from_utf16_lossy(&buffer); // works

            let jstr = util::evt_xml_to_json(xml);
            //println!("{}", xml);
            if let Ok(jstr_val) = jstr {
                println!("{}", jstr_val);
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
