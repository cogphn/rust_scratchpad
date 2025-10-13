
use std::thread;

use serde_json;
//use sea_orm::entity::prelude::*;



//#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
//#[sea_orm(table_name = "events")]
struct Event {
    pub id: Option<i64>,
    pub val1: String, 
    pub note: String
}


pub async fn write_to_disk(events: Vec<Event>, disk_db_connection: libsql::Connection) -> Result<(), Box <dyn std::error::Error>> {

    let tx = disk_db_connection.transaction().await?;
    let insert_query = "INSERT INTO events (val1, note) VALUES (?, ?);";
    for event in events { // this is fine... this is allegedly fine :/ 
        tx.execute(insert_query, (event.val1, event.note)).await?;
    }
    tx.commit().await?;

    Ok (())
}


#[tokio::main]
async fn main() -> Result<(),  Box<dyn std::error::Error>> {
    println!("[*] starting...");

    let localdbpath = "localcache.db";
    let db = libsql::Builder::new_local(":memory:").build().await.expect("    [!] Failed to open memory database");
    let disk_db = libsql::Builder::new_local(localdbpath).build().await.expect("    [!] Failed to open disk-based database");

    let ddl: &str = "CREATE TABLE IF NOT EXISTS events ( id INTEGER PRIMARY KEY, val1 TEXT, note TEXT);";

    let conn_mem = db.connect().unwrap();
    let conn_disk = disk_db.connect().unwrap();
    println!("    [i] creating tables...");

    conn_mem.execute(ddl, ()).await.unwrap();
    conn_disk.execute(ddl, ()).await.unwrap();


    println!("    [i] inserting test data (mem)...");

    let insert_query = "INSERT INTO events (val1, note) VALUES (?, ?);";
    conn_mem.execute(insert_query, ("test1", "in memory")).await.unwrap();
    conn_mem.execute(insert_query, ("test2", "in memory")).await.unwrap();
    conn_mem.execute(insert_query, ("test3", "in memory")).await.unwrap();
    thread::sleep(std::time::Duration::from_secs(2));

    println!("    [i] getting data from memory db...");
    let last_write_offset = 0;

    let mut results = conn_mem.query("SELECT id, val1, note FROM events LIMIT 100 OFFSET 0", ()).await?;

    let mut rowset: Vec<Event> = Vec::new();

    while let Some(row) = results.next().await? { 
        let evt = Event {
            id: None,
            val1: row.get::<String>(1).unwrap_or("".to_string()),
            note: row.get::<String>(2).unwrap_or("".to_string())
        };
        rowset.push(evt);
        println!("    [DBG]:[{}, {}, {}]", row.get::<i64>(0).unwrap(), row.get::<String>(1).unwrap(), row.get::<String>(2).unwrap());
    }

    println!("    [i] attempting bulk insert into disk db...");

    write_to_disk(rowset, conn_disk).await?;
    

    println!("[.] done.");
    Ok (())
}
