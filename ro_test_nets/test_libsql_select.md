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
tokio = { version = "1.47.1", features = ["rt", "macros", "rt-multi-thread"] }

~~~


### main.rs
~~~rust
use serde::Deserialize;
use serde::Serialize;

use std::error::Error;


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

    let cache_path = "c:\\progs\\dev\\rust_scratchpad\\ro1\\cache.db";

    let db = libsql::Builder::new_local(cache_path).build().await?;
    let conn = db.connect().unwrap();
    let query = "SELECT rawevent FROM events LIMIT 10";
    

    let mut results = conn.query(query, ()).await?;
    
    while let Some(row) = results.next().await? {
        println!("{:?}", row);
    }
    
    println!("[.] done");
    Ok(())
}

~~~
