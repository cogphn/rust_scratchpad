### Cargo.toml
~~~toml
[package]
name = "mpush"
version = "0.1.0"
edition = "2024"

[dependencies]
libsql = "0.9.24"
libsql-client = "0.33.4"
meilisearch-sdk = "0.30.0"
serde = { version = "1.0.228", features = ["derive"] } 
serde_json = "1.0.145"
tokio = { version = "1.47.1", features = ["rt", "macros", "rt-multi-thread"] }
~~~


### main.rs
~~~rust
use serde::Deserialize;
use serde::Serialize;

use std::error::Error;

use meilisearch_sdk::client::*;
//use serde_json::Value;


/*
#[derive(Debug, Serialize, Deserialize)]
struct SurrealConfig {
    url: String,
    apikey: String
}


struct SuperDBConfig {
    url: String
}
*/

#[tokio::main]
async fn main() -> Result<(),  Box<dyn std::error::Error>> {
    
    println!("[*] Starting...");

    let cache_path = " << path >> \\cache.db";

    let client = Client::new("http://<< addr >>:7700", Some("<< API Key >>"))?;
    let telem = client.index("telem");

    let db = libsql::Builder::new_local(cache_path).build().await?;
    let conn = db.connect().unwrap();
    

    let mut docid: i64 = 100;
    let mut offset: i64 = 0;

    let mut query = "SELECT rawevent FROM events LIMIT 100 OFFSET __OFFSET__";

    loop {
        let q = query.replace("__OFFSET__", &offset.to_string());
        let mut results = conn.query(&q, ()).await?;
        if results.next().await?.is_none() {
            break;
        }
        while let Some(row) = results.next().await? { // .... ouff
            let r: String = row.get::<String>(0).unwrap();
            let mut j_v: serde_json::Value = serde_json::from_str(&r)?;
            //j_v.insert("id".to_string(), serde_json::Value::from(docid));
            if let serde_json::Value::Object(map) = &mut j_v {
                map.insert("id".to_string(), serde_json::Value::from(docid));
            }
            let ret = telem.add_documents(&[j_v.clone()], Some("id")).await?;
            //println!("{:?}\n{:?}", ret, j_v);
            docid += 1;
        }
        offset += 100;
    }
    
    println!("[.] done");
    Ok(())
}

~~~
