//use std::fs;
//use serde_json::Value;
use chrono::{NaiveDateTime};
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;
//use surrealdb::Surreal;
//use surrealdb::engine::local::RocksDb;


use tokio::runtime::Runtime;

//use crate::cache;

pub const CACHE_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS events (  
  id INTEGER PRIMARY KEY,
  ts TIMESTAMP, 
  ts_type TEXT,
  src TEXT, 
  host TEXT,
  context1 TEXT, 
  context1_attrib TEXT,
  context2 TEXT, 
  context2_attrib TEXT,
  context3 TEXT, 
  context3_attrib TEXT,
  rawevent TEXT
);
"#;

#[derive(Serialize, Deserialize, Debug)]
pub struct GenericEventRecord {
    pub id: Option<i64>,
    pub ts: NaiveDateTime,
    pub ts_type: String,
    pub src: String,
    pub host: String,
    pub context1: String,
    pub context1_attrib: String,
    pub context2: String,
    pub context2_attrib: String,
    pub context3: String,
    pub context3_attrib: String,
    pub rawevent: String
}

pub static CACHE_CONN: OnceLock<libsql::Connection> = OnceLock::new();
pub static TOKIO_RUNTIME: OnceLock<Runtime> = OnceLock::new();
pub static CACHE_PATH: OnceLock<String> = OnceLock::new();

pub fn get_runtime() -> &'static Runtime {
    TOKIO_RUNTIME.get_or_init(|| {
        Runtime::new().expect("Failed to create Tokio runtime") //TODO: Review
    })
}

pub fn get_new_runtime() -> Result<Runtime, std::io::Error> {
    return Runtime::new();
}

pub async fn initialize_cache(cache_path: &str) -> Result<(), libsql::Error> {
    
    let db = libsql::Builder::new_local(cache_path).build().await?;
    let conn = db.connect().unwrap();
    conn.execute(CACHE_SCHEMA, ()).await.unwrap();
    CACHE_CONN.set(conn).map_err(|_| libsql::Error::ConnectionFailed(" [!] cache already initialized".into()))?;
    Ok(())
}

pub async fn insert_event(event: &GenericEventRecord) -> Result<(), libsql::Error> {
    let event_ts = event.ts.format("%Y-%m-%d %H:%M:%S").to_string();

    let query = r#"
    INSERT INTO events (ts, ts_type, src, host, context1, context1_attrib, context2, context2_attrib, context3, context3_attrib, rawevent)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
    "#;
    let _conn = match CACHE_CONN.get() {
        Some(c) => {
                let tx = c.transaction().await?;
                tx.reset().await;
                tx.execute(query, (
                    event_ts,
                    event.ts_type.clone(),
                    event.src.clone(),
                    event.host.clone(),
                    event.context1.clone(),
                    event.context1_attrib.clone(),
                    event.context2.clone(),
                    event.context2_attrib.clone(),
                    event.context3.clone(),
                    event.context3_attrib.clone(),
                    event.rawevent.clone()
                )).await?;
                tx.commit().await?;
            }
        None => {
            println!(" [!] error inserting event: cache not initialized");
            return Err(libsql::Error::ConnectionFailed(" [!] cache not initialized".into()));
        }
    };
        
    

    Ok(())
}

