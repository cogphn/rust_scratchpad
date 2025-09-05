use std::sync::atomic::AtomicU32;
use std::sync::atomic::Ordering;
use std::time::Duration;

use ferrisetw::parser::Parser;
use ferrisetw::provider::Provider;
use ferrisetw::provider::TraceFlags;
use ferrisetw::schema::Schema;
use ferrisetw::schema_locator::SchemaLocator;
use ferrisetw::trace::UserTrace;
use ferrisetw::EventRecord;
use ferrisetw::provider::EventFilter;

static N_EVENTS: AtomicU32 = AtomicU32::new(0);


/*
Review:

 - https://github.com/Microsoft/perfview/blob/main/src/TraceEvent/Parsers/Microsoft-Windows-TCPIP.cs#L19201


*/


fn kern_net_callback(record: &EventRecord, schema_locator: &SchemaLocator) {
    N_EVENTS.fetch_add(1, Ordering::SeqCst);

    match schema_locator.event_schema(record) {
        Err(err) => {
            println!("Unable to get the ETW schema for a TCPIP event: {:?}", err);
        }

        Ok(schema) => {
            parse_kern_net_event(&schema, record);
        }
    }
}

fn dns_etw_callback(record: &EventRecord, schema_locator: &SchemaLocator) {
    N_EVENTS.fetch_add(1, Ordering::SeqCst);

    match schema_locator.event_schema(record) {
        Err(err) => {
            println!("Unable to get the ETW schema for a DNS event: {:?}", err);
        }

        Ok(schema) => {
            parse_etw_dns_event(&schema, record);
        }
    }
}



fn ms_tcpip_etw_callback(record: &EventRecord, schema_locator: &SchemaLocator) {
    N_EVENTS.fetch_add(1, Ordering::SeqCst);

    match schema_locator.event_schema(record) {
        Err(err) => {
            println!("Unable to get the ETW schema for a TCPIP event: {:?}", err);
        }

        Ok(schema) => {
            parse_etw_tcp_event(&schema, record);
        }
    }
}


fn parse_etw_tcp_event(schema: &Schema, record: &EventRecord) {
    let parser = Parser::create(record, schema);
    
    /*
    Status: u32 or Vec<u8>

    
    */

    //looks like I can just grab field names from the EventData portion of the event log xml
    let event_desc = match record.event_id() {
        0 => "TcpIp/invalid",
        1214 => "TcpIp/packet_drop",
        1193 => "TcpIp/port_release",
        1038 => "TcpIp/connection_close_issued", // in-scope
        1040 => "TcpIp/connection_abort_complete", // in-scope
        1044 => "TcpIp/connection_abort", // in-scope
        1039 => "TcpIp/connection_abort_issued", // in-scope
        1479 => "TcpIp/connection_sent_RST", // in-scope
        1324 => "TcpIp/neighbor_state_change",
        1033 => "TcpIp/connect_complete", // in-scope
        1002 => "TcpIp/connect_request", // in-scope
        1013 => "TcpIp/connect_proceeding", // in-scope
        1001 => "TcpIp/endpoint_created", // in-scope
        1002 => "TcpIp/requested_to_connect",
        1003 => "TcpIp/inspect_connect_complete",
        1004 => "TcpIp/Tcb_is_going_to_output_SYN",
        1008 => "TcpIp/endpoint_bound",
        1009 => "TcpIp/endpoint_closed",
        1031 => "TcpIp/connection_connect_proceeding",
        1033 => "TcpIp/connect_complete", //in-scope
        1034 => "TcpIp/connection_attempt_failed",
        1042 => "TcpIp/connection_disconnect_issued",
        1043 => "TcpIp/connection_disconnect_completed",
        1051 => "TcpIp/connection_transition",
        1074 => "TcpIp/connection_received_data",
        1104 => "TcpIp/option_set_for_connection",
        1105 => "TcpIp/socket_set_for_connection",
        1156 => "TcpIp/connection_posted",
        1157 => "TcpIp/connection_indicated_bytes_accepted",
        1158 => "TcpIp/connection_delivery_satisfied",
        1159 => "TcpIp/connection_send_posted_bytes",
        1167 => "TcpIp/connection_measurement_complete",
        1169 => "Udp/sending_message",
        1170 => "UDP/delivering_bytes",
        1176 => "TcpIp/connection_delivering_FIN",
        1183 => "TcpIp/connection_connect_failed",
        1186 => "TcpIp/retransmitting_connection_attempt",
        1188 => "TcpIp/connection_send_keep_alive",
        1191 => "TcpIp/endpoint_or_connection_acquired_port_number",
        1192 => "TcpIp/connection_attempted_to_acquire_weak_reference_on_port",
        1193 => "TcpIp/endpoint_or_connection_released_port_number",
        1196 => "TcpIp/connection_BH_receive_ACK",
        1202 => "TcpIp/interface_rundown",
        1203 => "TcpIp/interface_linkspeed_change",
        1214 => "TcpIp/transport_dropped_packets",
        1215 => "TcpIp/network_layer_dropped_packet",
        1223 => "TcpIp/connection_committed",
        1229 => "TcpIp/send_queue_idle",
        1300 => "TcpIp/connection_exists", // in scope
        1330 => "TcpIp/connection_cumulative_ack_event",
        1332 => "TcpIp/connection_send-event",
        1351 => "TcpIp/connection_send_retransmit_round_with_snduna",
        1377 => "WFP-ALE/leaving_low_memory_state",
        1391 => "Udp/endpoint_created",
        1396 => "TcpIp/endpoint_bound_pid",
        1397 => "Udp/endpoint_closed",
        1398 => "Udp/endpoint_closed",
        1429 => "TcpIp/connection_cumulative_ack_event",
        1452 => "TcpIp/route_rundown",
        1454 => "INETINSPECT",
        1455 => "INETINSPECT",
        1466 => "WFP-ALE/remoteendpoint_insertion",
        1467 => "WFP-ALE/remote_endpoint_deletion",
        1475 => "TcpIp/CUBIC_hystart_state_change_event",
        1479 => "TcpIp/connection_sent_rst",
        1486 => "TcpIp/status_indication_received",
        1516 => "TcpIp/software_rsc",
        _ => "Unknown",
    };
    // Properties to find: 
    /*
     - Endpoint
     - NumMessages
     - NumBytes
     - LocalSockAddrLength
     - LocalSockAddr
     - RemoteSockAddrLength
     - RemoteSockAddr
     - Pid
     - ProcessStartKey
    */

    if record.event_id() == 1074 { 
        // connection received data 
        let tcb: Option<Vec<u8>> = parser.try_parse("Tcb").ok();
        let num_bytes: Option<u32> = parser.try_parse("NumBytes").ok();
        let seqno: Option<u32> = parser.try_parse("SeqNo").ok();

        println!(
            "event_id: {}, event_desc: {} \ntcb: {:?}\nnum_bytes: {}\nseqno: {}",
            record.event_id(),
            event_desc,
            tcb.map(|v| format!("{:X?}", v)).unwrap_or_default(),
            num_bytes.map(|u| u.to_string()).unwrap_or_default(),
            seqno.map(|u| u.to_string()).unwrap_or_default(),
            
        );
        println!("-----------------------------------");

    } else if record.event_id() == 1002 {
        let tcb: Option<Vec<u8>> = parser.try_parse("Tcb").ok();
        let local_address_length: Option<u32> = parser.try_parse("LocalAddressLength").ok();
        let local_address: Option<Vec<u8>> = parser.try_parse("LocalAddress").ok();
        let remote_address_length: Option<u32> = parser.try_parse("RemoteAddressLength").ok();
        let remote_address: Option<Vec<u8>> = parser.try_parse("RemoteAddress").ok();
        let new_state: Option<u32> = parser.try_parse("NewState").ok();
        let rexmit_count: Option<u32> = parser.try_parse("RexmitCount").ok();

        println!("addr_length: {:?}", local_address.clone().unwrap_or_default().len());

        let mut local_address_str = String::new();
        let laddr_length = local_address_length.unwrap_or_default() as usize;
        let local_address_trimmed = &local_address.clone().unwrap_or_default()[0..laddr_length/2].to_vec();
        for byte in &local_address_trimmed.clone() {
            local_address_str.push_str(&format!("{:02x?}", byte)); //works when tested against https://www.browserling.com/tools/hex-to-ip
        }

        println!("Tcb: {:?}\nLocal Address Length: {:?}\nLocal Address: {:x?} ({})\nRemote Address Length:{:?}\nRemote Address: {:?}\nNew State: {:?}\nRexmit Count: {:?}",
            tcb.map(|v| format!("{:X?}", v)).unwrap_or_default(), 
            local_address_length.unwrap_or_default(),
            local_address.unwrap_or_default(),
            local_address_str,
            remote_address_length.unwrap_or_default(),
            remote_address,
            new_state,
            rexmit_count
        );
        println!("-----------------------------------");

    } else if record.event_id() == 1001 {
        //TCP endpoint created 
        let satus: Option<u32> = parser.try_parse("Status").ok();
        let endpoint: Option<Vec<u8>> = parser.try_parse("Endpoint").ok();

        let attr1: Option<u32> = parser.try_parse("Endpoint").ok();
        let attr2: Option<u16> = parser.try_parse("Endpoint").ok();
        let attr3: Option<String> = parser.try_parse("Endpoint").ok();    
        let attr4: Option<String> = parser.try_parse("Endpoint").ok();
        let attr5: Option<Vec<u8>> = parser.try_parse("Endpoint").ok(); // binary data
        let attr6: Option<String> = parser.try_parse("Endpoint").ok();
        //let attr5: Option<Vec<u8>> = parser.try_parse("RawData").ok(); // binary data

        
        

        println!(
            "event_id: {:?}, event_desc: {:?}\nattr1: {:?}\nattr2: {:?}\nattr3: {:?}\nattr4:{:?}\nattr5: {:x?}\nattr6:{:?}",
            record.event_id(),
            event_desc,
            
            attr1.map(|u| u.to_string()).unwrap_or_default(),
            attr2.map(|u| u.to_string()).unwrap_or_default(),
            attr3.map(|u| u.to_string()).unwrap_or_default(),        
            attr4
                .map(|s| truncate(&s, 15).to_owned())
                .unwrap_or_default(),
            attr5.map(|v| format!("{:?}", v)).unwrap_or_default(),
            attr6
                .map(|s| truncate(&s, 15).to_owned())
                .unwrap_or_default(),
        );
        println!("-----------------------------------");
    } else {
        let status: Option<u32> = parser.try_parse("Status").ok();
        let endpoint: Option<Vec<u8>> = parser.try_parse("Endpoint").ok(); // fix display - looks like a hex string in the event viewer 
        let num_messages: Option<u32> = parser.try_parse("NumMessages").ok();
        let num_bytes: Option<u32> = parser.try_parse("NumBytes").ok();
        let num_bytes: Option<u32> = parser.try_parse("NumBytes").ok();



        let attr1: Option<u32> = parser.try_parse("Pid").ok();
        let attr2: Option<u16> = parser.try_parse("Pid").ok();
        let attr3: Option<String> = parser.try_parse("Pid").ok();    
        let attr4: Option<String> = parser.try_parse("Pid").ok();
        let attr6: Option<String> = parser.try_parse("Pid").ok();
        //let attr5: Option<Vec<u8>> = parser.try_parse("RawData").ok(); // binary data
        let attr5: Option<Vec<u8>> = parser.try_parse("Pid").ok(); // binary data
        
        /*
        println!(
            "event_id: {:?}, event_desc: {:?}, status: {:?}\nattr1: {:?}\nattr2: {:?}\nattr3: {:?}\nattr4:{:?}\nattr5: {:x?}\nattr6:{:?}",
            record.event_id(),
            event_desc,
            status.map(|u| u.to_string()).unwrap_or_default(),
            attr1.map(|u| u.to_string()).unwrap_or_default(),
            attr2.map(|u| u.to_string()).unwrap_or_default(),
            attr3.map(|u| u.to_string()).unwrap_or_default(),        
            attr4
                .map(|s| truncate(&s, 15).to_owned())
                .unwrap_or_default(),
            attr5.map(|v| format!("{:?}", v)).unwrap_or_default(),
            attr6
                .map(|s| truncate(&s, 15).to_owned())
                .unwrap_or_default(),
        );
        println!("-----------------------------------");
        */
        
    }

    
    
    
}

fn parse_kern_net_event(schema: &Schema, record: &EventRecord) {
    let parser = Parser::create(record, schema);
    // let event_timestamp = filetime_to_datetime(schema.timestamp());

    //let local_addr: Option<String> = parser.try_parse("LocalAddress").ok();
    let local_addr: Option<String> = parser.try_parse("saddr").ok();
    let local_port: Option<u16> = parser.try_parse("sport").ok();
    let remote_addr: Option<String> = parser.try_parse("daddr").ok();
    let remote_port: Option<u16> = parser.try_parse("dport").ok();
    let process_id: Option<u32> = parser.try_parse("PID").ok();    
    //let app_name: Option<String> = parser.try_parse("AppName").ok();

    println!(
        "event_id: {:?},  process_id: {:?}, local_port:{:?}, local_addr:{:?}, remote_port:{:?}, remote_addr:{:?}",
        record.event_id(),
        process_id.map(|u| u.to_string()).unwrap_or_default(),
        local_port.map(|u| u.to_string()).unwrap_or_default(),
        local_addr
            //.map(|s| truncate(&s, 15).to_owned())
            .unwrap_or_default(),
        remote_port.map(|u| u.to_string()).unwrap_or_default(),
        remote_addr
            .map(|s| truncate(&s, 15).to_owned())
            .unwrap_or_default(),
        /*app_name
            .map(|s| truncate(&s, 20).to_owned())
            .unwrap_or_default(),*/
    );
}

fn parse_etw_dns_event(schema: &Schema, record: &EventRecord) {
    let parser = Parser::create(record, schema);
    // let event_timestamp = filetime_to_datetime(schema.timestamp());

    let requested_fqdn: Option<String> = parser.try_parse("QueryName").ok();
    let query_type: Option<u32> = parser.try_parse("QueryType").ok();
    let query_options: Option<u64> = parser.try_parse("QueryOptions").ok();
    let query_status: Option<u32> = parser
        .try_parse("QueryStatus")
        .or_else(|_err| parser.try_parse("Status"))
        .ok();
    let query_results: Option<String> = parser.try_parse("QueryResults").ok();

    println!(
        "{:4} {:4}  {:16} {:2} | Requested FQDN: {:10} |  Query results: {}",
        record.event_id(),
        query_status.map(|u| u.to_string()).unwrap_or_default(),
        query_options
            .map(|u| format!("{:16x}", u))
            .unwrap_or_default(),
        query_type.map(|u| format!("{:2}", u)).unwrap_or_default(),
        requested_fqdn
            .map(|s| truncate(&s, 10).to_owned())
            .unwrap_or_default(),
        query_results
            .map(|s| truncate(&s, 30).to_owned())
            .unwrap_or_default(),
    );
}

fn main() {
    env_logger::init(); // this is optional. This makes the (rare) error logs of ferrisetw to be printed to stderr

    let _dns_provider = Provider::by_guid("1c95126e-7eea-49a9-a3fe-a378b03ddb4d") // Microsoft-Windows-DNS-Client
        .add_callback(dns_etw_callback)
        .trace_flags(TraceFlags::EVENT_ENABLE_PROPERTY_PROCESS_START_KEY)
        .build();


    let _kern_net_provider = Provider::by_guid("7dd42a49-5329-4832-8dfd-43d979153a88") //Microsoft-Windows-Kernel-Network
        .add_callback(kern_net_callback)
        .trace_flags(TraceFlags::EVENT_ENABLE_PROPERTY_PROCESS_START_KEY)
        .build();


    let ms_tcpip_provider = Provider::by_guid("2F07E2EE-15DB-40F1-90EF-9D7BA282188A") // Microsoft-Windows-TCPIP
        .add_callback(ms_tcpip_etw_callback)
        .trace_flags(TraceFlags::EVENT_ENABLE_PROPERTY_PROCESS_START_KEY)
        //.filter(EventFilter::new(0,0,0)) 
        .build();


    let trace = UserTrace::new()
        .enable(ms_tcpip_provider)
        .start_and_process()
        .unwrap();
    
    /*

    let trace = UserTrace::new()
        .enable(ms_tcpip_provider)
        .start_and_process()
        .unwrap();
    */
    //println!("ID   Status Options         Ty Name       Results");

    std::thread::sleep(Duration::new(10, 0));

    trace.stop().unwrap(); // This is not required, as it will automatically be stopped on Drop
    println!("Done: {:?} events", N_EVENTS);
}

fn truncate(s: &str, n: usize) -> &str {
    match s.get(..n) {
        Some(x) => x,
        None => s,
    }
}
