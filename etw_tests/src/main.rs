use ferrisetw::parser::Parser;
use ferrisetw::provider::*;
use ferrisetw::schema_locator::SchemaLocator;
use ferrisetw::trace::*;
use ferrisetw::EventRecord;
use std::time::Duration;

fn main() {
    env_logger::init(); // this is optional. This makes the (rare) error logs of ferrisetw to be printed to stderr

    let image_load_callback =
        |record: &EventRecord, schema_locator: &SchemaLocator| match schema_locator
            .event_schema(record)
        {
            Ok(schema) => {
                let opcode = record.opcode();
                if opcode == 10 {
                    let name = schema.provider_name();
                    println!("ProviderName: {}", name);
                    let parser = Parser::create(record, &schema);
                    // Fully Qualified Syntax for Disambiguation
                    match parser.try_parse::<String>("FileName") {
                        Ok(filename) => println!("FileName: {}", filename),
                        Err(err) => println!("Error: {:?} getting Filename", err),
                    };
                }
            }
            Err(err) => println!("Error {:?}", err),
        };

    let process_start_callback = 
        |record: &EventRecord, schema_locator: &SchemaLocator| match schema_locator
            .event_schema(record)
        {
            Ok(schema) => {
                let opcode = record.opcode();
                //if opcode == 10 { // ??
                    let name = schema.provider_name();
                    println!("ProviderName: {}", name);
                    println!("Opcode: {}", opcode);
                    println!("eventid {}",record.event_id() );
                    let parser = Parser::create(record, &schema);
                    // Fully Qualified Syntax for Disambiguation
                    
                    match parser.try_parse::<String>("ImageName") {
                        Ok(iname) => println!("ImageName: {}", iname),
                        Err(err) => println!("Error: {:?} getting Image Name", err),
                    };

                //} else {
                //    println!(" [?] the opcode is not 10..... not sure what that means");
                //}
            }
            Err(err) => println!("Error {:?}", err),
        };

    let regisevent_callback =
        |record: &EventRecord, schema_locator: &SchemaLocator| match schema_locator
            .event_schema(record)
        {
            Ok(schema) => {
                let opcode = record.opcode();
                //if opcode == 11 {
                    let name = schema.provider_name();
                    println!("ProviderName: {},  Opcode: {},    Event ID: {}", 
                        name, opcode, record.event_id()
                    );
                    // not sure why the eventid is always 0
                    
                    println!("event_name: {}", record.event_name() ); //blank :/

                    let parser = Parser::create(record, &schema);

                    match parser.try_parse::<String>("KeyName") {
                        Ok(keyname) => println!("KeyName: {}", keyname),
                        Err(err) => println!("Error: {:?} getting KeyName", err),
                    };
                //}
            }
            Err(err) => println!("Error {:?}", err),
        };

    
    //let provider = Provider::kernel(&kernel_providers::IMAGE_LOAD_PROVIDER)
    let proc_provider = Provider::kernel(&kernel_providers::PROCESS_PROVIDER)
        //.add_callback(image_load_callback)
        .add_callback(process_start_callback)
        .build();

    let reg_provider = Provider::kernel(&kernel_providers::REGISTRY_PROVIDER)
        .add_callback(regisevent_callback)
        .build();

    let image_load_provider = Provider::kernel(&kernel_providers::IMAGE_LOAD_PROVIDER)
        .add_callback(image_load_callback)
        .build();

    let kernel_trace = KernelTrace::new()
        .named(String::from("MyKernelProvider"))
        .enable(reg_provider)
        //.stop_if_exist(true)
        .start_and_process()
        .unwrap();

    std::thread::sleep(Duration::new(20, 0));
    kernel_trace.stop().unwrap(); // This is not required, as it will automatically be stopped on Drop
}
