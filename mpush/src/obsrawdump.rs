use argparse::{ArgumentParser, Store};
use std::fs::File;
use std::io::{Write, BufWriter};


#[tokio::main]
async fn main() -> Result<(),  Box<dyn std::error::Error>> {
    
    println!("[*] Starting...");
    // Example: cargo run --bin rawdump -- --outfile dump1.jsonl --cache E:\dev\rust_scratchpad\ro1\cachedb_backup.db
    let mut cache_path = "".to_string();
    let mut outfile_path = "events.jsonl".to_string();
        
    {
        let mut ap = ArgumentParser::new();
        
        ap.refer(&mut cache_path).add_option(
            &["-c", "--cache"],
            Store,
            "Path to cache file"
        ).required();

        ap.refer(&mut outfile_path).add_option(
            &["-o", "--outfile"],
            Store,
            "Path to output file"
        ).required();
        
        ap.parse_args_or_exit();    
    }
    

    let outfile = File::create(&outfile_path).expect("[!] error creating output file");

    let mut writer = BufWriter::new(outfile);
            
    

    let db = libsql::Builder::new_local(&cache_path).build().await?;
    let conn = db.connect().unwrap();

    let mut offset: i64 = 0;

    let query = "SELECT rawevent, id FROM events LIMIT 1000 OFFSET __OFFSET__";    
    println!("    [*] Cache file: {}", cache_path);
    println!("    [*] output file: {}", outfile_path);

    println!("    [*] Running jsonl dump...");

    let delim = "\n".to_string();
    loop {
        let q = query.replace("__OFFSET__", &offset.to_string());
        let mut results = conn.query(&q, ()).await?;
        if results.next().await?.is_none() {
            break;
        }        
        while let Some(row) = results.next().await? {
            let r: String = row.get::<String>(0).unwrap();            
            writer.write(r.as_bytes()).expect("[!] error writing to output file");
            writer.write(delim.as_bytes()).expect("[!] error writing to output file");
        }
        offset += 100;
    }    
    println!("[.] done");
    Ok(())
}
