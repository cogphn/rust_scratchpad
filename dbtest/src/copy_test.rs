
use libsql::params;






pub async fn copy_table(src_db_connection: libsql::Connection, dest_db_connection: libsql::Connection, batchsize: i64) -> Result<(), Box <dyn std::error::Error>> {

    let q_template = r#"
    SELECT ts, src, host, context1, context1_attrib, context2, context2_attrib, context3, context3_attrib, rawevent
    FROM events LIMIT ?1
    OFFSET ?2
    "#;

    let mut offset: i64 = 0;

    

    loop {
        let mut results = src_db_connection.query(&q_template, params![batchsize, offset]).await?;
        if results.next().await?.is_none() {
            break;
        }

        let tx = dest_db_connection.transaction().await?;
        let insert_query = "INSERT INTO events (ts, src, host, context1, context1_attrib, context2, context2_attrib, context3, context3_attrib, rawevent) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);";
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
        println!("[DBG] num_rows: {}", num_rows);
        if num_rows == 0 {
            break;
        }
        offset += num_rows;
        println!("[DBG] offset: {}", offset);
    }



    Ok (())
}


#[tokio::main]
async fn main() -> Result<(),  Box<dyn std::error::Error>> {
    println!("[*] starting...");


    let srcpath = "E:\\dev\\rust_scratchpad\\ro1\\cache.db";
    let destpath = "E:\\tmp\\cache_copy.db";

    let ddl =  r#"
CREATE TABLE IF NOT EXISTS events (  
  id INTEGER PRIMARY KEY,
  ts TIMESTAMP, 
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

    let srcdb = libsql::Builder::new_local(srcpath).build().await?;
    let destdb = libsql::Builder::new_local(destpath).build().await?;

    let src_conn = srcdb.connect().unwrap();
    let dest_conn = destdb.connect().unwrap();

    src_conn.execute(ddl, ()).await.unwrap();
    dest_conn.execute(ddl, ()).await.unwrap();

    copy_table(src_conn, dest_conn, 10).await?;

    println!("[.] Done!");
    Ok (())
}
