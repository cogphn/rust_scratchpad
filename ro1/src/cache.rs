use chrono::{NaiveDateTime};
use serde::{Deserialize, Serialize};
use std::{sync::OnceLock};
use std::sync::Arc;

use tokio::runtime::Runtime;
use libsql::params;
use std::sync::atomic::{AtomicBool, Ordering};
//use tokio::runtime;

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

pub static DISK_DB_CONN: OnceLock<libsql::Connection> = OnceLock::new();

static mut SYNC_OFFSET: i64 = 0;

pub fn get_runtime() -> &'static Runtime {
    TOKIO_RUNTIME.get_or_init(|| {
        Runtime::new().expect("Failed to create Tokio runtime") //TODO: Review
    })
}

pub fn get_new_runtime() -> Result<Runtime, std::io::Error> {
    return Runtime::new();
}

pub async fn initialize_cache(cache_path: &str) -> Result<(), libsql::Error> {
    
    //let db = libsql::Builder::new_local(cache_path).build().await?;
    let db = libsql::Builder::new_local(":memory:").build().await?;
    let conn = db.connect().unwrap();
    conn.execute(CACHE_SCHEMA, ()).await.unwrap();
    CACHE_CONN.set(conn).map_err(|_| libsql::Error::ConnectionFailed(" [!] cache already initialized".into()))?;

    let disk_db: libsql::Database = libsql::Builder::new_local(cache_path).build().await?;
    let disk_conn = disk_db.connect().unwrap();
    disk_conn.execute(CACHE_SCHEMA, ()).await.unwrap();
    DISK_DB_CONN.set(disk_conn).map_err(|_| libsql::Error::ConnectionFailed(" [!] cache already initialized".into()))?;
    Ok(())
}

pub async fn last_write() -> Result<(), Box<dyn std::error::Error>> {
    let select_query = r#"
    SELECT ts, src, host, context1, context1_attrib, context2, context2_attrib, context3, context3_attrib, rawevent
    FROM events LIMIT ?1
    OFFSET ?2
    "#;
    let insert_query = "INSERT INTO events (ts, src, host, context1, context1_attrib, context2, context2_attrib, context3, context3_attrib, rawevent) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);";

    let num_persisted_rows_query = "SELECT MAX(id) as maxid FROM events";

    

    let persist_conn = match DISK_DB_CONN.get() {
        Some(conn) => conn,
        None => {
            return Err("[!] could not get connection for persistent cache DB".into());
        }
    };

    let src_db_connection = match CACHE_CONN.get() {
        Some(conn) => conn,
        None => {
            return Err("[!] could not get connection for in-memory cache".into());
        }
    };

    let mut mr_rows = persist_conn.query(num_persisted_rows_query, ()).await.unwrap();
    let mr_row = mr_rows.next().await.unwrap().unwrap();
    let mut current_offset = match mr_row.get::<i64>(0) {
        Ok(val) => val,
        Err(_) => 0
    };

    if current_offset == 0 {
        return Ok(());
    }

    println!("[DBG - cache::last_write]  current offset: {}", current_offset);
    let batchsize: i64 = 1000;

    loop {
        let mut results = src_db_connection.query(&select_query, params![batchsize, current_offset]).await?;
        if results.next().await?.is_none() {
            break;
        }

        let tx = persist_conn.transaction().await?;
        let mut num_rows: i64 = 0;
        while let Some(row) = results.next().await? {
            let ts = row.get::<String>(0).unwrap();
            let src = row.get::<String>(1).unwrap();
            let host = row.get::<String>(2).unwrap();
            let context1 = row.get::<String>(3).unwrap();
            let context1_attrib = row.get::<String>(4).unwrap();

            let context2 = row.get::<String>(5).unwrap();
            let context2_attrib = row.get::<String>(6).unwrap();

            let context3 = row.get::<String>(7).unwrap();
            let context3_attrib = row.get::<String>(8).unwrap();

            let rawevent = row.get::<String>(9).unwrap();
            tx.execute(insert_query, (ts, src, host, context1, context1_attrib, context2, context2_attrib, context3, context3_attrib, rawevent)).await?;
            num_rows +=1;
        }
        tx.commit().await?;
        //println!("[DBG] num_rows: {}", num_rows);
        if num_rows == 0 {
            break;
        }
        current_offset += num_rows;
    }

    Ok(())


}

pub fn db_disk_sync(running:Arc<AtomicBool>) -> Result<(), Box<dyn std::error::Error>> {

    let select_query = r#"
    SELECT ts, src, host, context1, context1_attrib, context2, context2_attrib, context3, context3_attrib, rawevent
    FROM events LIMIT ?1
    OFFSET ?2
    "#;
    let insert_query = "INSERT INTO events (ts, src, host, context1, context1_attrib, context2, context2_attrib, context3, context3_attrib, rawevent) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);";

    let num_persisted_rows_query = "SELECT MAX(id) as maxid FROM events";

    let batchsize: i64 = 1000;

    let persist_conn = match DISK_DB_CONN.get() {
        Some(conn) => conn,
        None => {
            return Err("[!] could not get connection for persistent cache DB".into());
        }
    };

    let c = match CACHE_CONN.get() {
        Some(conn) => conn,
        None => {
            return Err("[!] could not get connection for in-memory DB".into());
        }
    };


    while running.load(Ordering::SeqCst) == true {

        std::thread::sleep(std::time::Duration::new(5, 0));

        let rt = Runtime::new().unwrap();

        rt.block_on(async {
            let mut mid_rows = persist_conn.query(num_persisted_rows_query, ()).await.unwrap();
            let mid_row = mid_rows.next().await.unwrap().unwrap();
            let poffset = match mid_row.get::<i64>(0) { 
                Ok(val) => val,
                Err(_) => 0
            };

            println!("[DBG - cache::db_disk_sync]; offset: {}", poffset);

            let mut results = c
                .query(select_query, params![batchsize, poffset])
                .await.unwrap();
            if !results.next().await.unwrap().is_none() {
                // there are results, allegedly
                //let mut numrows: i64 = 0;
                let tx = persist_conn.transaction().await.unwrap();
                
                while let Some(row) = results.next().await.unwrap() {
                    let ts = row.get::<String>(0).unwrap();
                    let src = row.get::<String>(1).unwrap();
                    let host = row.get::<String>(2).unwrap();
                    let context1 = row.get::<String>(3).unwrap();
                    let context1_attrib = row.get::<String>(4).unwrap();

                    let context2 = row.get::<String>(5).unwrap();
                    let context2_attrib = row.get::<String>(6).unwrap();

                    let context3 = row.get::<String>(7).unwrap();
                    let context3_attrib = row.get::<String>(8).unwrap();

                    let rawevent = row.get::<String>(9).unwrap();
                    let _ = tx.execute(insert_query, (ts, src, host, context1, context1_attrib, context2, context2_attrib, context3, context3_attrib, rawevent)).await;
                    //numrows += 1;
                }
                let _ = tx.commit().await;
            }
        });

    } //while loop

    println!("[!] stopping dbsync");

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

