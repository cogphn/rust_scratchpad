use ferrisetw::parser::Parser;
use ferrisetw::provider::*;
use ferrisetw::schema_locator::SchemaLocator;
use ferrisetw::trace::*;
use ferrisetw::EventRecord;
use std::time::Duration;

fn main() {
    env_logger::init(); // this is optional. This makes the (rare) error logs of ferrisetw to be printed to stderr

    let process_callback =
        |record: &EventRecord, schema_locator: &SchemaLocator| match schema_locator
            .event_schema(record)
        {
            Ok(schema) => {
                let event_id = record.event_id();
                if event_id == 2 {
                    let name = schema.provider_name();
                    println!("Name: {}", name);
                    let parser = Parser::create(record, &schema);
                    let process_id: u32 = parser.try_parse("ProcessID").unwrap();
                    let exit_code: u32 = parser.try_parse("ExitCode").unwrap();
                    let image_name: String = parser.try_parse("ImageName").unwrap();
                    println!(
                        "PID: {}, ExitCode: {}, ImageName: {}",
                        process_id, exit_code, image_name
                    );
                }

            }
            Err(err) => println!("Error {:?}", err),
        };

    
    let reg_callback =
        |record: &EventRecord, schema_locator: &SchemaLocator| match schema_locator
            .event_schema(record)
        {
            Ok(schema) => {
                let event_id = record.event_id();
                let name = schema.provider_name();
                let timestamp = record.timestamp();



                if event_id == 1 {
                    println!("[{}][{}] Name: {}", timestamp, event_id, name);    
                    let parser = Parser::create(record, &schema);
                    //let timestamp = record.timestamp();
                    let status: u32 = parser.try_parse("Status").unwrap();
                    let disposition: u32 = parser.try_parse("Disposition").unwrap();
                    let base_name: String = parser.try_parse("BaseName").unwrap();
                    let relative_name: String = parser.try_parse("RelativeName").unwrap();
                    println!(
                        "status: {}, disposition: {}, BaseName: {}, RelativeName: {}",
                        status, disposition, base_name, relative_name
                    );
                } else if event_id == 5 {
                        println!("[{}][{}] Name: {}", timestamp, event_id, name);
                        let parser = Parser::create(record, &schema);
                        //let timestamp = record.timestamp();
                        let status: u32 = parser.try_parse("Status").unwrap();
                        let dtype: u32 = parser.try_parse("Type").unwrap();
                        let key_name: String = parser.try_parse("KeyName").unwrap();
                        let value_name: String = parser.try_parse("ValueName").unwrap();
                        println!(
                            "status: {}, Type: {}, KeyName: {}, ValueName: {}",
                            status, dtype, key_name, value_name
                        );
                }
                
            }
            Err(err) => println!("Error {:?}", err),
        };


    let kernfile_callback =
        |record: &EventRecord, schema_locator: &SchemaLocator| match schema_locator
            .event_schema(record)
        {
            Ok(schema) => {
                let event_id = record.event_id();
                let name = schema.provider_name();
                let timestamp = record.timestamp();

                if event_id == 26 {
                    let event_description = "DeletePath".to_string();
                    println!("[{}][{}] Name: {}, {}", timestamp, event_id, name, event_description);
                } else if event_id == 28 {
                    let event_description = "SetLinkPath".to_string();
                    println!("[{}][{}] Name: {}, {}", timestamp, event_id, name, event_description);
                    let parser = Parser::create(record, &schema);

                    
                } else if event_id == 30 {
                    let event_description = "CreateNewFile".to_string();
                    println!("[{}][{}] Name: {}, {}", timestamp, event_id, name, event_description);
                    let parser = Parser::create(record, &schema);

                    let irp: Option<Vec<u8>> = parser.try_parse("Irp").ok();
                    let thread_id: Option<Vec<u8>> =parser.try_parse("ThreadId").ok();
                    let file_object: Option<Vec<u8>> =parser.try_parse("FileObject").ok(); 
                    let create_options: Option<u32> = parser.try_parse("CreateOptions").ok();
                    let create_attributes: Option<u32> = parser.try_parse("CreateAttributes").ok();
                    let share_access: Option<u32> = parser.try_parse("ShareAccess").ok();
                    let file_name: Option<String> = parser.try_parse("FileName").ok();
                    let issuing_thread_id: Option<Vec<u8>> = parser.try_parse("IssuingThreadId").ok();

                    println!("{:?}, {:?}, {:?}, {:?}, {:?}, {:?}, {:?}, {:?}",
                        irp, thread_id, file_object, create_options, create_attributes, share_access, file_name, issuing_thread_id
                    );

                };
            }
            Err(err) => println!("Error {:?}", err),
        };


    let process_provider = Provider::by_guid(0x22fb2cd6_0e7b_422b_a0c7_2fad1fd0e716) // Microsoft-Windows-Kernel-Process
        .add_callback(process_callback)
        .build();

    let reg_provider = Provider::by_guid(0x70eb4f03_c1de_4f73_a051_33d13d5413bd)
        .add_callback(reg_callback)
        .build();

    let file_eid_filter = EventFilter::ByEventIds(vec![30, 28, 26]);
    let file_provider = Provider::by_guid(0xedd08927_9cc4_4e65_b970_c2560fb5c289) //Microsoft-Windows-Kernel-File
        .add_callback(kernfile_callback)
        .add_filter(file_eid_filter)
        .build();

    let (_user_trace, handle) = UserTrace::new()
        .named(String::from("trace101"))
        //.enable(process_provider)
        //.enable(reg_provider)
        .enable(file_provider)
        .start()
        .unwrap();

    // This example uses `process_from_handle` rather than the more convient `start_and_process`, because why not.
    std::thread::spawn(move || {
        let status = UserTrace::process_from_handle(handle);
        // This code will be executed when the trace stops. Examples:
        // * when it is dropped
        // * when it is manually stopped (either by user_trace.stop, or by the `logman stop -ets MyTrace` command)
        println!("Trace ended with status {:?}", status);
    });

    std::thread::sleep(Duration::new(20, 0));

    // user_trace will be dropped (and stopped) here
}
