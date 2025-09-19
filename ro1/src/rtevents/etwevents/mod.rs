use std::sync::atomic::AtomicU32;
use std::sync::atomic::Ordering;
//use std::time::Duration;

use ferrisetw::parser::Parser;
use ferrisetw::provider::Provider;
use ferrisetw::provider::TraceFlags;
use ferrisetw::schema::Schema;
use ferrisetw::schema_locator::SchemaLocator;
use ferrisetw::trace::UserTrace;
use ferrisetw::EventRecord;
use ferrisetw::provider::EventFilter;

static N_EVENTS: AtomicU32 = AtomicU32::new(0);

pub mod templates;
use super::cache;
use super::parser;

use ferrisetw::trace::TraceError;


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


fn ms_kernreg_etw_callback(record: &EventRecord, schema_locator: &SchemaLocator) {
    N_EVENTS.fetch_add(1, Ordering::SeqCst);

    match schema_locator.event_schema(record) {
        Err(err) => {
            println!("Unable to get the ETW schema for a Registry event: {:?}", err);
        }

        Ok(schema) => {
            parse_etw_reg_event(&schema, record);
        }
    }
}

fn secaudit_etw_callback(record: &EventRecord, schema_locator: &SchemaLocator) {
    N_EVENTS.fetch_add(1, Ordering::SeqCst);

    match schema_locator.event_schema(record) {
        Err(err) => {
            println!("Unable to get the ETW schema for a Security Auditing event: {:?}", err);
        }

        Ok(schema) => {
            parse_etw_secaudit_event(&schema, record);
        }
    }
}



fn parse_etw_secaudit_event(schema: &Schema, record: &EventRecord) {
    let parser = Parser::create(record, schema);


    let event_desc = match record.event_id() {      
        // DNS events   
        4688 => "task_04688",
        _ => "not_tracked"
    };

    let event_id =  record.event_id();
    let event_desc = event_desc.to_string();
    let ts_str =  record.timestamp().to_string(); 
    let provider_name = schema.provider_name();
    let new_process_name: Option<String> = parser.try_parse("NewProcessName").ok();
    

    println!("{}    {}  {}  {:?}  {:?}",
        event_id, event_desc, ts_str, provider_name, new_process_name    
    );
}


fn parse_etw_tcp_event(schema: &Schema, record: &EventRecord) {
    let parser = Parser::create(record, schema);
    
    let event_desc = match record.event_id() {        
        1002 => "TcpRequestConnect",
        //1014 => "TcpAccpetListenerRouteLookupFailure",
        //1015 => "TcpAcceptListenerInsertionFailure",
        //1016 => "TcpAcceptListenerRejected",
        
        1017 => "TcpAcceptListenerComplete",
        /*
        //1018 => "TcpConnectTcbFailedAf",
        //1019 => "TcpConnectTcbFailedCompartment",
        //1020 => "TcpConnectTcbFailedInspect",
        //1021 => "TcpConnectTcbFailedRoute",
        //1022 => "TcpConnectTcbSkipRateLimit",
        //1023 => "TcpConnectTcbPassRateLimit",
        //1024 => "TcpConnectTcbCheckRateLimit",
        
        1026 => "TcpRateLimitPathRelease",
        1027 => "TcpConnectTcbRateLimitRelease",
        
        //1028 => "TcpRateLimitPathCancel",
        //1029 => "TcpConnectTcbCancel",
        //1030 => "TcpConnectTcbFailInsertion",
        */
        //1031 => "TcpConnectTcbProceeding",
        
        //1032 => "TcpConnectTcbRateLimitCancel",
        1033 => "TcpConnectTcbComplete",
        /*
        //1034 => "TcpConnectTcbFailure",
        //1035 => "TcpConnectTcbFailInspectConnectComplete",
        //1036 => "TcpConnectTcbFailSessionState",
        //1037 => "TcpConnectTcbFailDontFragment",
        
        1038 => "TcpCloseTcbRequest",
        1039 => "TcpAbortTcbRequest",
        1040 => "TcpAbortTcbComplete",
        1043 => "TcpDisconnectTcbComplete",
        
        //1044 => "TcpShutdownTcb", // TODO: Review
        
        1045 => "TcpConnectTcbTimeout",
        1046 => "TcpDisconnectTcbRtoTimeout",
        1047 => "TcpDisconnectTcbKeepaliveTimeout",
        1048 => "TcpDisconnectTcbTimeout",
        1049 => "TcpConnectTcbEstatsFailed",
        
        //1050 => "TcpConnectFailedPortAcquire",
        //1092 => "TcpAutoTuningBegin",
        //1093 => "TcpAutoTuningEnd",
        //1094 => "TcpAutoTuningFailedRttEstimation",
        //1095 => "TcpAutoTuningFailedBandwidthEstimation",
        //1096 => "TcpAutoTuningFailedAllocationFailure",
        //1097 => "TcpAutoTuningChangeRcvBufferSize",
        //1182 => "TcpInitiateSynRstValidation",
        //1183 => "TcpConnectTcbFailedRcvdRst",
        
        //1184 => "TcpConnectionTerminatedRcvdRst",
        //1185 => "TcpConnectionTerminatedRcvdSyn",
        
        //1186 => "TcpConnectRestransmit",
        //1187 => "TcpDataTransferRestransmit",
        //1200 => "TcpDisconnectTcbZeroWindowTimeout",
        //1201 => "TcpDisconnectTcbFinWait2Timeout",
        //1293 => "Ndkpi_Read",
        //1294 => "Ndkpi_Write",
        1300 => "TcpConnectionRundown",
        //1357 => "TcpipAoacFailFast",
        
        //1364 => "TcpInsertConnectionTuple",
        //1365 => "TcpRemoveConnectionTuple",
        //1374 => "RemoteEndpoint",
        //1375 => "RemoteEndpoint1375",
        //1382 => "TcpInspectConnectWithNameResContext",
        //1466 => "RemoteEndpoint1466",
        //1467 => "RemoteEndpoint1467",
        //1468 => "TcpSystemAbortTcb",
        */
        1477 => "TcpConnectionSummary1477",
        
        _ => "Other",
    };

    if event_desc == "Other"{ // TODO: fix filters
        return;
    }

    
    let mut net_event_data = templates::GeneralNetEvent {
        ts_str: record.timestamp().to_string(),
        event_id: record.event_id(),
        event_description: event_desc.to_string(),
        provider_name: schema.provider_name(),
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
    
    // DBG2
    let nestr = serde_json::to_string(&net_event_data).unwrap();
    let er = parser::netevent_to_er(net_event_data).unwrap();

    cache::get_runtime().spawn(async move {
        cache::insert_event(&er).await.ok();
    });

    println!("{}", nestr);
    
    
}


// netconns 
pub fn start_tcp_event_observer() -> Result<UserTrace, TraceError> {

    let ms_tcpip_provider = Provider::by_guid("2F07E2EE-15DB-40F1-90EF-9D7BA282188A") // Microsoft-Windows-TCPIP
        .add_callback(ms_tcpip_etw_callback)
        .trace_flags(TraceFlags::EVENT_ENABLE_PROPERTY_PROCESS_START_KEY)
        //.filter(EventFilter::new(0,0,0)) 
        .build();

    let trace = UserTrace::new()
        .enable(ms_tcpip_provider)
        .start_and_process();
    
    return trace;
}

pub fn stop_tcp_event_observer(trace: UserTrace) -> Result<(), TraceError> {
    return trace.stop();
}

// DNS

fn win_dns_etw_callback(record: &EventRecord, schema_locator: &SchemaLocator) {
    N_EVENTS.fetch_add(1, Ordering::SeqCst);

    match schema_locator.event_schema(record) {
        Err(err) => {
            println!("Unable to get the ETW schema for a DNS event: {:?}", err);
        }

        Ok(schema) => {
            parse_dns_event(&schema, record);
        }
    }
}

fn parse_dns_event(schema: &Schema, record: &EventRecord) {
    let parser = Parser::create(record, schema);


    let event_desc = match record.event_id() {      
        // DNS events   
        1001 => "DnsServerForInterface",
        3006 => "task_03006",
        3008 => "task_03008",
        3009 => "task_03009",
        3016 => "task_03016",
        3018 => "task_03018",
        3019 => "task_03019",
        3010 => "task_03010",
        3011 => "task_03011",
        3020 => "task_03020",
        3013 => "task_03013",
        _ => "not_tracked"
    };

    let mut dns_event = templates::GenericDnsEvent {
        event_id: record.event_id(),
        event_desc: event_desc.to_string(),
        ts_str: record.timestamp().to_string(), 
        provider_name: schema.provider_name(),
        location: parser.try_parse("Location").ok(),
        context: parser.try_parse("Context").ok(),
        interface: parser.try_parse("Interface").ok(),
        total_server_count: parser.try_parse("TotalServerCount").ok(),
        index: parser.try_parse("Index").ok(),
        dynamic_address: parser.try_parse("DynamicAddress").ok(),
        address_length: parser.try_parse("AddressLength").ok(),
        address: parser.try_parse("Address").ok(),
        error_code: parser.try_parse("ErrorCode").ok(),
        dns_suffix: parser.try_parse("DnsSuffix").ok(),
        ad_suffix: parser.try_parse("AdSuffix").ok(),
        query_name: parser.try_parse("QueryName").ok(),
        dns_address_length: parser.try_parse("DnsAddressLength").ok(),
        dns_address: parser.try_parse("DnsAddress").ok(),
        key_name: parser.try_parse("KeyName").ok(),
        dns_sec_validation_required: parser.try_parse("DnsSecValidationRequired").ok(),
        dns_query_over_ip_sec: parser.try_parse("DnsQueryOverIPSec").ok(),
        dns_encryption: parser.try_parse("DnsEncryption").ok(),
        direct_access_server_list: parser.try_parse("DirectAccessServerList").ok(),
        remote_ipsec: parser.try_parse("RemoteIPSEC").ok(),
        remote_encryption: parser.try_parse("RemoteEncryption").ok(),
        proxy_type: parser.try_parse("ProxyType").ok(),
        proxy_name: parser.try_parse("ProxyName").ok(),
        rule_name: parser.try_parse("RuleName").ok(),
        response_question: parser.try_parse("ResponseQuestion").ok(),
        generic_server_list: parser.try_parse("GenericServerList").ok(),
        idn_config: parser.try_parse("IdnConfig").ok(),
        query_type: parser.try_parse("QueryType").ok(),
        query_options: parser.try_parse("QueryOptions").ok(),
        status: parser.try_parse("Status").ok(),
        server_list: parser.try_parse("ServerList").ok(),
        is_network_query: parser.try_parse("IsNetworkQuery").ok(),
        network_query_index: parser.try_parse("NetworkQueryIndex").ok(),
        interface_index: parser.try_parse("InterfaceIndex").ok(),
        is_async_query: parser.try_parse("IsAsyncQuery").ok(),
        query_status: parser.try_parse("QueryStatus").ok(),
        query_results: parser.try_parse("QueryResults").ok(),
        is_parallel_network_query: parser.try_parse("IsParallelNetworkQuery").ok(),
        network_index: parser.try_parse("NetworkIndex").ok(),
        interface_count: parser.try_parse("InterfaceCount").ok(),
        adapter_name: parser.try_parse("AdapterName").ok(),
        local_address: parser.try_parse("LocalAddress").ok(),
        dns_server_address: parser.try_parse("DNSServerAddress").ok(),
        dns_server_ip_address: parser.try_parse("DnsServerIpAddress").ok(),
        response_status: parser.try_parse("ResponseStatus").ok(),
        host_name: parser.try_parse("HostName").ok(),
        adapter_suffix_name: parser.try_parse("AdapterSuffixName").ok(),
        dns_server_list: parser.try_parse("DnsServerList").ok(),
        sent_update_server: parser.try_parse("SentUpdateServer").ok(),
        ipaddress: parser.try_parse("Ipaddress").ok(),
        warning_code: parser.try_parse("WarningCode").ok(),
        next_state: parser.try_parse("NextState").ok(),
        update_reason_code: parser.try_parse("UpdateReasonCode").ok(),
        source_address: parser.try_parse("SourceAddress").ok(),
        source_port: parser.try_parse("SourcePort").ok(),
        destination_address: parser.try_parse("DestinationAddress").ok(),
        destination_port: parser.try_parse("DestinationPort").ok(),
        protocol: parser.try_parse("Protocol").ok(),
        reference_context: parser.try_parse("ReferenceContext").ok(),
        if_guid: parser.try_parse("IfGuid").ok(),
        if_index: parser.try_parse("IfIndex").ok(),
        if_luid: parser.try_parse("IfLuid").ok()
    };

    let dnsstr = serde_json::to_string(&dns_event).unwrap();
    let er = parser::dnsevent_to_er(dns_event).unwrap();

    cache::get_runtime().spawn(async move {
        cache::insert_event(&er).await.ok();
    });

    //println!("{}", dnsstr);


}


fn parse_etw_reg_event(schema: &Schema, record: &EventRecord) {
    let parser = Parser::create(record, schema);
    
    let event_desc = match record.event_id() {      
        // Reg events   
        1 => "task_0CreateKey",
        2 => "task_0OpenKey",
        3 => "task_0DeleteKey",
        4 => "task_0QueryKey",
        5 => "task_0SetValueKey",
        6 => "task_0DeleteValueKey",
        7 => "task_0QueryValueKey",
        _ => "not_tracked"
    };

    let event_id = record.event_id();
    let provider_name = schema.provider_name();
    let timestamp = record.timestamp();

    let mut reg_event = templates::GenericRegEvent {
		event_id: record.event_id(),
		event_desc: event_desc.to_string(),
		ts_str: record.timestamp().to_string(),
		provider_name: schema.provider_name(),

        key_object: parser.try_parse("KeyObject").ok(),
		status: parser.try_parse("Status").ok(),
		etype: parser.try_parse("Type").ok(),
		data_size: parser.try_parse("DataSize").ok(),
		key_name: parser.try_parse("KeyName").ok(),
		value_name: parser.try_parse("ValueName").ok(),
		captured_data_size: parser.try_parse("CapturedDataSize").ok(),
		captured_data: parser.try_parse("CapturedData").ok(),
		previous_data_type: parser.try_parse("PreviousDataType").ok(),
		previous_data_size: parser.try_parse("PreviousDataSize").ok(),
		previous_data_captured_size: parser.try_parse("PreviousDataCapturedSize").ok(),
		previous_data: parser.try_parse("PreviousData").ok(),
		base_object: parser.try_parse("BaseObject").ok(),
		disposition: parser.try_parse("Disposition").ok(),
		base_name: parser.try_parse("BaseName").ok(),
		relative_name: parser.try_parse("RelativeName").ok(),
        bytes_recovered:   parser.try_parse("BytesReceived").ok(),
        entry_count: parser.try_parse("EntryCount").ok(),
        file_size: parser.try_parse("FileSize").ok(),
        flush_flags: parser.try_parse("FlushFlags").ok(),
        hive_file_path: parser.try_parse("HiveFilePath").ok(),
        hive_mount_point: parser.try_parse("HiveMountPoint").ok(),
        index: parser.try_parse("Index").ok(),
        bytes_gathered: parser.try_parse("BytesGathered").ok(),
        bytes_written: parser.try_parse("BytesWritten").ok(),
        flags: parser.try_parse("Flags").ok(),
        info_class: parser.try_parse("InfoClass").ok(),
        source_file: parser.try_parse("SourceFile").ok(),
        source_key_path: parser.try_parse("SourceKeyPath").ok(),
        status_code: parser.try_parse("StatusCode").ok(),
        total_entry_size: parser.try_parse("TotalEntrySize").ok(),
        writes_issued: parser.try_parse("WritesIssued").ok()
    };

    let regstr = serde_json::to_string(&reg_event).unwrap();
    let er = parser::regevent_to_er(reg_event).unwrap();

    cache::get_runtime().spawn(async move {
        cache::insert_event(&er).await.ok();
    });
}


pub fn start_dns_event_observer() -> Result<UserTrace, TraceError> {

    let win_dns_provider = Provider::by_guid("1c95126e-7eea-49a9-a3fe-a378b03ddb4d") // Microsoft-Windows-DNS-Client
        .add_callback(win_dns_etw_callback)
        .trace_flags(TraceFlags::EVENT_ENABLE_PROPERTY_PROCESS_START_KEY)
        .build();

    let trace = UserTrace::new()
        .enable(win_dns_provider)
        .start_and_process();

    return trace;
}

pub fn stop_dns_event_observer(trace: UserTrace) -> Result<(), TraceError> {
    return trace.stop();
}


pub fn start_etw_providers() -> Result<UserTrace, TraceError> { 

    let dns_eid_filter = EventFilter::ByEventIds(vec![1001, 3006, 3008, 3009, 3016, 3018, 3019, 3010, 3011, 3020, 3013]);
    let tcp_eid_filter = EventFilter::ByEventIds(vec![1002]);
    let reg_eid_filter = EventFilter::ByEventIds(vec![1,3,5,6]);
    let secaudit_eid_filter = EventFilter::ByEventIds(vec![4688]);
    
    let win_dns_provider = Provider::by_guid("1c95126e-7eea-49a9-a3fe-a378b03ddb4d") // Microsoft-Windows-DNS-Client
        .add_filter(dns_eid_filter)
        .add_callback(win_dns_etw_callback)
        .trace_flags(TraceFlags::EVENT_ENABLE_PROPERTY_PROCESS_START_KEY)
        .build();

    let ms_tcpip_provider = Provider::by_guid("2F07E2EE-15DB-40F1-90EF-9D7BA282188A") // Microsoft-Windows-TCPIP
        .add_filter(tcp_eid_filter)
        .add_callback(ms_tcpip_etw_callback)
        .trace_flags(TraceFlags::EVENT_ENABLE_PROPERTY_PROCESS_START_KEY)
        //.filter(EventFilter::new(0,0,0)) 
        .build();

    let ms_reg_provider = Provider::by_guid(0x70eb4f03_c1de_4f73_a051_33d13d5413bd) // Microsoft-Windows-Kernel-Registry
        .add_filter(reg_eid_filter)
        .add_callback(ms_kernreg_etw_callback)
        //.trace_flags(TraceFlags::EVENT_ENABLE_PROPERTY_PROCESS_START_KEY)
        .build();

    let win_secaudit_provider = Provider::by_guid(0x54849625_5478_4994_a5ba_3e3b0328c30d)
        .add_filter(secaudit_eid_filter)
        .add_callback(secaudit_etw_callback)
        .build();


    let trace = UserTrace::new()
        .enable(win_dns_provider)
        //.enable(ms_tcpip_provider)
        .enable(ms_reg_provider)
        //.enable(win_secaudit_provider)
        .start_and_process();

    trace
}


pub fn stop_etw_providers(trace: UserTrace) ->  Result<(), TraceError> {
    return trace.stop();
}
