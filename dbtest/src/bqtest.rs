use google_cloud_bigquery::client::{Client, ClientConfig};
use google_cloud_bigquery::http::dataset::list::ListDatasetsRequest;
//use std::env;


#[tokio::main]
async fn main()-> Result<(), Box<dyn std::error::Error>> {
    println!("[*] starting...");

    let project_id = "<<redacted>>";
    let config = ClientConfig::new_with_auth().await?;
    let client = Client::new(config.0).await?;

    let request = Some(ListDatasetsRequest {        
        all: Some(true).is_some(),
        max_results: Some(100),
        ..Default::default()
    });
    
    match client.dataset().list(&project_id, request.as_ref()).await {
        Err(e) => {
            eprintln!("Error: {:?}", e);
        },
        Ok(x) => {
            // println!("[DBG] {:?}", x);            
            for ds in x {
                println!("id: {}, dataset_id: {}", ds.id, ds.dataset_reference.dataset_id);
                // println!("{:?}", ds);
            }
        
        }
    }
    //println!("{:?}", request);
    
    println!("[.] Done.");
    Ok(())

} // main
