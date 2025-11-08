use serde::Deserialize;
use serde::Serialize;
use meilisearch_sdk::client::*;
use argparse::{ArgumentParser, Store};


#[derive(Debug, Serialize, Deserialize)]
struct SurrealConfig {
    url: String,
    apikey: Option<String>
}


#[tokio::main]
async fn main() -> Result<(),  Box<dyn std::error::Error>> {
    
    println!("[*] Starting...");

    let mut cache_path = "".to_string();
    let mut mconfig_path = "".to_string();
    {
        let mut ap = ArgumentParser::new();
        ap.refer(&mut mconfig_path).add_option(
            &["-m", "--meili-config"],
            Store,
            "Path to meilisearch config file"
        ).required();
        ap.refer(&mut cache_path).add_option(
            &["-c", "--cache"],
            Store,
            "Path to cache file"
        ).required();
        ap.parse_args_or_exit();    
    }
    let mconfig_str = std::fs::read_to_string(&mconfig_path)?;
    let mconfig: SurrealConfig = serde_json::from_str(&mconfig_str)?;
    

    let client = Client::new(mconfig.url, mconfig.apikey)?;
    let telem = client.index("telem3");

    let db = libsql::Builder::new_local(&cache_path).build().await?;
    let conn = db.connect().unwrap();

    let mut offset: i64 = 0;

    let query = "SELECT rawevent, id FROM events LIMIT 1000 OFFSET __OFFSET__";

    println!("    [*] Config file: {}", mconfig_path);
    println!("    [*] Cache file: {}", cache_path);

    println!("    [*] Running import...");
    loop {
        let q = query.replace("__OFFSET__", &offset.to_string());
        let mut results = conn.query(&q, ()).await?;
        if results.next().await?.is_none() {
            break;
        }
        let mut records = Vec::new();
        while let Some(row) = results.next().await? {
            let r: String = row.get::<String>(0).unwrap();
            let mut j_v: serde_json::Value = serde_json::from_str(&r)?;
            if let serde_json::Value::Object(map) = &mut j_v {
                map.insert("id".to_string(), serde_json::Value::from(row.get::<i64>(1).unwrap()));
            }
            records.push(j_v);
        }
        let _ret = telem.add_documents(&records, Some("id")).await?;
        offset += 100;
    }    
    println!("[.] done");
    Ok(())
}
