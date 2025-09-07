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

mod templates;

/*
Review:

 - https://github.com/Microsoft/perfview/blob/main/src/TraceEvent/Parsers/Microsoft-Windows-TCPIP.cs#L19201

*/


fn hex_to_ipv4(hex_str: &str) -> Option<String> {
    if hex_str.len() != 16 {
        Some("Invalid arguments");
    }
    let bytes = (0..16)
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex_str[i..i + 2], 16).ok())
        .collect::<Option<Vec<u8>>>()?;
    let ip_addr = format!("{}.{}.{}.{}", bytes[4], bytes[5], bytes[6], bytes[7]);
    Some(ip_addr)
}

/*
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
*/
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
        1002 => "TcpRequestConnect",
        1014 => "TcpAccpetListenerRouteLookupFailure",
        1015 => "TcpAcceptListenerInsertionFailure",
        1016 => "TcpAcceptListenerRejected",
        1017 => "TcpAcceptListenerComplete",
        1018 => "TcpConnectTcbFailedAf",
        1019 => "TcpConnectTcbFailedCompartment",
        1020 => "TcpConnectTcbFailedInspect",
        1021 => "TcpConnectTcbFailedRoute",
        1022 => "TcpConnectTcbSkipRateLimit",
        1023 => "TcpConnectTcbPassRateLimit",
        1024 => "TcpConnectTcbCheckRateLimit",
        1026 => "TcpRateLimitPathRelease",
        1027 => "TcpConnectTcbRateLimitRelease",
        1028 => "TcpRateLimitPathCancel",
        1029 => "TcpConnectTcbCancel",
        1030 => "TcpConnectTcbFailInsertion",
        1031 => "TcpConnectTcbProceeding",
        1032 => "TcpConnectTcbRateLimitCancel",
        1033 => "TcpConnectTcbComplete",
        1034 => "TcpConnectTcbFailure",
        1035 => "TcpConnectTcbFailInspectConnectComplete",
        1036 => "TcpConnectTcbFailSessionState",
        1037 => "TcpConnectTcbFailDontFragment",
        1038 => "TcpCloseTcbRequest",
        1039 => "TcpAbortTcbRequest",
        1040 => "TcpAbortTcbComplete",
        1043 => "TcpDisconnectTcbComplete",
        1044 => "TcpShutdownTcb",
        1045 => "TcpConnectTcbTimeout",
        1046 => "TcpDisconnectTcbRtoTimeout",
        1047 => "TcpDisconnectTcbKeepaliveTimeout",
        1048 => "TcpDisconnectTcbTimeout",
        1049 => "TcpConnectTcbEstatsFailed",
        1050 => "TcpConnectFailedPortAcquire",
        1092 => "TcpAutoTuningBegin",
        1093 => "TcpAutoTuningEnd",
        1094 => "TcpAutoTuningFailedRttEstimation",
        1095 => "TcpAutoTuningFailedBandwidthEstimation",
        1096 => "TcpAutoTuningFailedAllocationFailure",
        1097 => "TcpAutoTuningChangeRcvBufferSize",
        1182 => "TcpInitiateSynRstValidation",
        1183 => "TcpConnectTcbFailedRcvdRst",
        1184 => "TcpConnectionTerminatedRcvdRst",
        1185 => "TcpConnectionTerminatedRcvdSyn",
        1186 => "TcpConnectRestransmit",
        1187 => "TcpDataTransferRestransmit",
        1200 => "TcpDisconnectTcbZeroWindowTimeout",
        1201 => "TcpDisconnectTcbFinWait2Timeout",
        1293 => "Ndkpi_Read",
        1294 => "Ndkpi_Write",
        1300 => "TcpConnectionRundown",
        1357 => "TcpipAoacFailFast",
        1364 => "TcpInsertConnectionTuple",
        1365 => "TcpRemoveConnectionTuple",
        1374 => "RemoteEndpoint",
        1375 => "RemoteEndpoint1375",
        1382 => "TcpInspectConnectWithNameResContext",
        1466 => "RemoteEndpoint1466",
        1467 => "RemoteEndpoint1467",
        1468 => "TcpSystemAbortTcb",
        1477 => "TcpConnectionSummary1477",
        _ => "Other",
    };

    if event_desc == "Other"{ // TODO: fix filters
        return;
    }
    println!("----START----");

    //println!("{:?}", record.timestamp());

    let mut net_event_data = templates::GeneralNetEvent {
        timestamp: record.timestamp().to_string(),
        event_id: record.event_id(),
        event_description: event_desc.to_string(),
        tcb: parser.try_parse("Tcb").ok(), 
        local_address_length: parser.try_parse("LocalAddressLength").ok(),
        local_address: parser.try_parse("LocalAddress").ok(),
        remote_address_length: parser.try_parse("RemoteAddressLength").ok(),
        remote_address: parser.try_parse("RemoteAddress").ok(),
        new_state: parser.try_parse("NewState").ok(),
        rexmit_count: parser.try_parse("RexmitCount").ok(),
        status: parser.try_parse("Status").ok(),
        process_id: parser.try_parse("ProcessId").ok(),
        compartment: parser.try_parse("Compartment").ok(),
        path: parser.try_parse("Path").ok(),
        buffer_size: parser.try_parse("BufferSize").ok(),
        ndk_qp: parser.try_parse("NdkQp").ok(),
        request_context: parser.try_parse("RequestContext").ok(),
        sge_address: parser.try_parse("SgeAddress").ok(),
        sge_length: parser.try_parse("SgeLength").ok(),
        sge_memory_region_token: parser.try_parse("SgeMemoryRegionToken").ok(),
        num_sge: parser.try_parse("NumSge").ok(),
        flags: parser.try_parse("Flags").ok(),
        sge_index: parser.try_parse("SgeIndex").ok(),
        remote_token: parser.try_parse("RemoteToken").ok(),
        state: parser.try_parse("State").ok(),
        pid: parser.try_parse("Pid").ok(),
        request_type: parser.try_parse("RequestType").ok(),
        tcb_or_endpoint: parser.try_parse("TcbOrEndpoint").ok(),
        interface_index: parser.try_parse("InterfaceIndex").ok(),
        address_length: parser.try_parse("AddressLength").ok(),
        remote_port: parser.try_parse("RemotePort").ok(),
        local_port: parser.try_parse("LocalPort").ok(),
        partition_id: parser.try_parse("PartitionId").ok(),
        num_entries: parser.try_parse("NumEntries").ok(),
        name_res_context: parser.try_parse("NameResContext").ok(),
        dns_name: parser.try_parse("DnsName").ok(),
        data_bytes_out: parser.try_parse("DataBytesOut").ok(),
        data_bytes_in: parser.try_parse("DataBytesIn").ok(),
        data_segments_out: parser.try_parse("DataSegmentsOut").ok(),
        data_segments_in: parser.try_parse("DataSegmentsIn").ok(),
        segments_out: parser.try_parse("SegmentsOut").ok(),
        segments_in: parser.try_parse("SegmentsIn").ok(),
        non_recov_da: parser.try_parse("NonRecovDa").ok(),
        non_recov_da_episodes: parser.try_parse("NonRecovDaEpisodes").ok(),
        dup_acks_in: parser.try_parse("DupAcksIn").ok(),
        bytes_retrans: parser.try_parse("BytesRetrans").ok(),
        timeouts: parser.try_parse("Timeouts").ok(),
        spurious_rto_detections: parser.try_parse("SpuriousRtoDetections").ok(),
        fast_retran: parser.try_parse("FastRetran").ok(),
        max_ssthresh: parser.try_parse("MaxSsthresh").ok(),
        max_ss_cwnd: parser.try_parse("MaxSsCwnd").ok(),
        max_ca_cwnd: parser.try_parse("MaxCaCwnd").ok(),
        snd_lim_trans_rwin: parser.try_parse("SndLimTransRwin").ok(),
        snd_lim_time_rwin: parser.try_parse("SndLimTimeRwin").ok(),
        snd_lim_bytes_rwin: parser.try_parse("SndLimBytesRwin").ok(),
        snd_lim_trans_cwnd: parser.try_parse("SndLimTransCwnd").ok(),
        snd_lim_time_cwnd: parser.try_parse("SndLimTimeCwnd").ok(),
        snd_lim_bytes_cwnd: parser.try_parse("SndLimBytesCwnd").ok(),
        snd_lim_trans_snd: parser.try_parse("SndLimTransSnd").ok(),
        snd_lim_time_r_snd: parser.try_parse("SndLimTimeRSnd").ok(),
        snd_lim_bytes_r_snd: parser.try_parse("SndLimBytesRSnd").ok(),
        connection_time_ms: parser.try_parse("ConnectionTimeMs").ok(),
        timestamps_enabled: parser.try_parse("TimestampsEnabled").ok(),
        rtt_us: parser.try_parse("RttUs").ok(),
        min_rtt_us: parser.try_parse("MinRttUs").ok(),
        max_rtt_us: parser.try_parse("MaxRttUs").ok(),
        syn_retrans: parser.try_parse("SynRetrans").ok(),
        congestion_algorithm: parser.try_parse("CongestionAlgorithm").ok(),
        cwnd: parser.try_parse("Cwnd").ok(),
        ss_thresh: parser.try_parse("SSThresh").ok(),
        rcv_wnd: parser.try_parse("RcvWnd").ok(),
        rcv_buf: parser.try_parse("RcvBuf").ok(),
        snd_wnd: parser.try_parse("SndWnd").ok(),
        process_start_key: parser.try_parse("ProcessStartKey").ok(),
        local_address_ipv4: "".to_string(),
        remote_address_ipv4: "".to_string()
    };

    let mut local_address_str = String::new();
    let laddr_length = net_event_data.local_address_length.unwrap_or_default() as usize;
    let mut remote_address_str = String::new();
    let raddr_length = net_event_data.remote_address_length.unwrap_or_default() as usize;

    
    if laddr_length > 15 {
        let local_address_trimmed = &net_event_data.local_address.clone().unwrap_or_default()[0..laddr_length/2].to_vec();
        for byte in &local_address_trimmed.clone() {
            local_address_str.push_str(&format!("{:02x?}", byte)); //
        }
        net_event_data.local_address_ipv4 = hex_to_ipv4(&local_address_str).unwrap_or_default();
    }
    
    if raddr_length > 15 {
        let raddr_trimmed = &net_event_data.remote_address.clone().unwrap_or_default()[0..raddr_length/2].to_vec();
        for byte in &raddr_trimmed.clone() {
            remote_address_str.push_str(&format!("{:02x?}", byte));
        }
        net_event_data.remote_address_ipv4 = hex_to_ipv4(&remote_address_str).unwrap_or_default();
    }
    
    // DBG1
    //println!(
    // "[DBG][{}][{}], {:?}, {:?}, {}, {}, laddr_length: {}, raddr_length: {}",
    // record.event_id(),
    // event_desc,
    // net_event_data.local_address,
    // net_event_data.remote_address,
    // net_event_data.local_address_ipv4,
    // net_event_data.remote_address_ipv4,
    // laddr_length,
    // raddr_length
    //);

    // DBG2
    let z = serde_json::to_string(&net_event_data).unwrap();
    println!("{}", z);
    println!("-----END-----");
    
    //println!("{}", serde_json::to_string(&net_event_data).unwrap());
    
}

/*
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
*/

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
    
    /*
    let _kern_net_provider = Provider::by_guid("7dd42a49-5329-4832-8dfd-43d979153a88") //Microsoft-Windows-Kernel-Network
        .add_callback(kern_net_callback)
        .trace_flags(TraceFlags::EVENT_ENABLE_PROPERTY_PROCESS_START_KEY)
        .build();
    */

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
