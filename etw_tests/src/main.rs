use std::sync::atomic::AtomicU32;
use std::sync::atomic::Ordering;
use std::time::Duration;

use ferrisetw::parser::Parser;
use ferrisetw::provider::Provider;
use ferrisetw::provider::TraceFlags;
use ferrisetw::schema::Schema;
use ferrisetw::schema_locator::SchemaLocator;
use ferrisetw::trace::UserTrace;
use ferrisetw::trace::KernelTrace;
use ferrisetw::EventRecord;
use ferrisetw::provider::EventFilter;

static N_EVENTS: AtomicU32 = AtomicU32::new(0);



/*

<data name="Interface" inType="win:UnicodeString" />
<data name="TotalServerCount" inType="win:UInt32" />
<data name="Index" inType="win:UInt32" />
<data name="DynamicAddress" inType="win:UInt8" map="DnsIpTypeMap" />
<data name="AddressLength" inType="win:UInt32" />
<data name="Address" inType="win:Binary" length="AddressLength" />

      <template tid="task_03006Args">
            <data name="QueryName" inType="win:UnicodeString" />
            <data name="QueryType" inType="win:UInt32" />
            <data name="QueryOptions" inType="win:UInt64" />
            <data name="ServerList" inType="win:UnicodeString" />
            <data name="IsNetworkQuery" inType="win:UInt32" />
            <data name="NetworkQueryIndex" inType="win:UInt32" />
            <data name="InterfaceIndex" inType="win:UInt32" />
            <data name="IsAsyncQuery" inType="win:UInt32" />
          </template>
          <template tid="task_03008Args">
            <data name="QueryName" inType="win:UnicodeString" />
            <data name="QueryType" inType="win:UInt32" />
            <data name="QueryOptions" inType="win:UInt64" />
            <data name="QueryStatus" inType="win:UInt32" />
            <data name="QueryResults" inType="win:UnicodeString" />

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

fn etw_callback(record: &EventRecord, schema_locator: &SchemaLocator) {
    N_EVENTS.fetch_add(1, Ordering::SeqCst);

    match schema_locator.event_schema(record) {
        Err(err) => {
            println!("Unable to get the ETW schema for a DNS event: {:?}", err);
        }

        Ok(schema) => {
            parse_etw_event(&schema, record);
        }
    }
}

fn parse_etw_event(schema: &Schema, record: &EventRecord) {
    let parser = Parser::create(record, schema);

    
    let interface: Option<String> = parser.try_parse("Interface").ok();
    let total_server_count: Option<u32> = parser.try_parse("TotalServerCount").ok();
    let index: Option<u32> = parser.try_parse("Index").ok();
    let dynamic_address: Option<u8> = parser.try_parse("DynamicAddress").ok();
    let address_length: Option<u32> = parser.try_parse("AddressLength").ok();
    let address: Option<Vec<u8>> = parser.try_parse("Address").ok();


    let query_name : Option<String> = parser.try_parse("QueryName").ok();
    let query_type : Option<u32> = parser.try_parse("QueryType").ok();
    let query_options : Option<u64> = parser.try_parse("QueryOptions").ok();
    let server_list : Option<String> = parser.try_parse("ServerList").ok();
    let is_network_query : Option<u32> = parser.try_parse("IsNetworkQuery").ok();
    let network_query_index : Option<u32> = parser.try_parse("NetworkQueryIndex").ok();
    let interface_index : Option<u32> = parser.try_parse("InterfaceIndex").ok();
    let is_async_query : Option<u32> = parser.try_parse("IsAsyncQuery").ok();

    let query_status : Option<u32> = parser.try_parse("QueryStatus").ok();
    let query_results: Option<String> = parser.try_parse("QueryResults").ok();

    let status: Option<u32> = parser.try_parse("Status").ok();
    let network_index: Option<u32> = parser.try_parse("NetworkIndex").ok();



    
    let mut address_str = String::new();
    let addr_length_usize = address_length.unwrap_or_default() as usize;
    let mut address_str_pretty = String::new();

    if addr_length_usize >15 {
        let address_trimmed = &address.clone().unwrap_or_default()[0..addr_length_usize/2].to_vec();
        for byte in &address_trimmed.clone() {
            address_str.push_str(&format!("{:02x?}", byte)); //
        }
        address_str_pretty = hex_to_ipv4(&address_str).unwrap_or_default();
    }
    
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
        3013 => "",

        _ => "unknown"
    };


    if record.event_id() == 1001 {
        println!(
        "--------\n{:?}, {:?}, {:?}, {:?}, {:?}, {:?}, {:?}, {:?}\n--------",
        record.event_id(),
        event_desc,

        interface,
        total_server_count,
        index,
        dynamic_address,
        address_length,
        address_str_pretty
        );
    } else if record.event_id() == 3006 {
                println!(
            "--------\n{:?}, {:?}, {:?}, {:?}, {:?}, {:?}, {:?}, {:?}, {:?}, {:?}\n--------",
            record.event_id(),
            event_desc,

            query_name,
            query_type,
            query_options,
            server_list,
            is_network_query, 
            network_query_index,
            interface_index,
            is_async_query        

        );

    } else if record.event_id() == 3008 {
        println!(
            "--------\n{:?}, {:?}, {:?}, {:?}, query_options: {:?}, query_status: {:?}, query_results: {:?}\n--------",
            record.event_id(),
            event_desc,

            query_name,
            query_type,
            query_options,
            query_status,
            query_results        

        );
    } else if record.event_id() == 3013 {
        println!(
            "--------\n{:?}, {:?}, query_name: {:?}, query_status: {:?}, query_results: {:?}\n--------",
            record.event_id(),
            event_desc,

            query_name,
            status,
            query_results        

        );
    } else if record.event_id() == 3018 {
        println!(
            "--------\n{:?}, {:?}, query_name: {:?}, query_type: {:?}, query_options: {:?}, status: {:?}, query_results: {:?}\n--------",
            record.event_id(),
            event_desc,

            query_name,
            query_type,
            query_options,
            status,
            query_results
        );
    } else if record.event_id() == 3020 {
        println!(
            "--------\n{:?}, {:?}, query_name: {:?}, network_index: {:?}, interface_index: {:?}, status: {:?}, query_results: {:?}\n--------",
            record.event_id(),
            event_desc,

            query_name,
            network_index,
            interface_index,
            status,
            query_results
        );
    } else {
        println!("[*] i'm not tracking that...");
    }

}

fn main() {
    env_logger::init(); // this is optional. This makes the (rare) error logs of ferrisetw to be printed to stderr

    
    let my_provider = Provider::by_guid("1c95126e-7eea-49a9-a3fe-a378b03ddb4d") // Microsoft-Windows-DNS-Client
        .add_callback(etw_callback)
        .trace_flags(TraceFlags::EVENT_ENABLE_PROPERTY_PROCESS_START_KEY)
        .build();
    

    let trace = UserTrace::new()
        .enable(my_provider)
        .start_and_process()
        .unwrap();
    
 
    std::thread::sleep(Duration::new(30, 0));

    trace.stop().unwrap(); // This is not required, as it will automatically be stopped on Drop
    println!("Done: {:?} events", N_EVENTS);
}

fn truncate(s: &str, n: usize) -> &str {
    match s.get(..n) {
        Some(x) => x,
        None => s,
    }
}
