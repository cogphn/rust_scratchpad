use sqlx::postgres::PgPoolOptions;
//use sqlx::Connection;
use futures_util::TryStreamExt;
use sqlx::Row;


#[tokio::main]
async fn main() -> Result<(), sqlx::Error> {
    
    println!("[*] starting...");
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect("postgres://postgres:<<redacted>>@dev01/dfir").await?;
        

    //let num_files_query = "select sum(1) as rc from filequeue";

    let query = "select * from parse_definitions";

    let mut rows = sqlx::query(query).fetch(&pool);

    while let Some(row) = rows.try_next().await? {
        let id: i32 = row.try_get("id").expect("[!] error getting parse definition id");
        let filename: &str = row.try_get("artifact_class").expect("[!] error getting filename");
        println!("id: {}, artifact_class: {}", id, filename);
    }

    println!("[.] Done!");
    Ok(())

}