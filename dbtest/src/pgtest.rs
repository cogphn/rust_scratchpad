use sqlx::postgres::PgPoolOptions;
//use sqlx::Connection;
use futures_util::TryStreamExt;
use sqlx::Row;
use std::env;

#[tokio::main]
async fn main() -> Result<(), sqlx::Error> {

    // run like so: 
    // PG_PWD='<< password for postgres user >>' cargo run --bin pgtest
    let pg_pwd: String = match env::var("PG_PWD") {
        Ok(p) => p,
        Err(_e) => {
            println!("    [!] password not specified - trying a blank password");
            "".to_string()
        }
    };
    
    
    let constr = "postgres://postgres:".to_owned() + &pg_pwd +"@dev01/dfir";
    
    println!("[*] starting...");
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&constr).await?;
        

    //let num_files_query = "select sum(1) as rc from filequeue";

    let query = "select id, artifact_class from parse_definitions";

    let mut rows = sqlx::query(query).fetch(&pool);

    while let Some(row) = rows.try_next().await? {
        let id: i32 = row.try_get("id").expect("[!] error getting parse definition id");
        let filename: &str = row.try_get("artifact_class").expect("[!] error getting filename");
        println!("[DATA] id: {}, artifact_class: {}", id, filename);
    }

    println!("[.] Done!");
    Ok(())

}