//use duckdb::{Connection, Result};
use std::fs;
use serde_json::Value;
use chrono::{DateTime, Utc, NaiveDateTime, ParseError};
use serde::{Deserialize, Serialize};

pub const CACHE_SCHEMA: &str = r#"
CREATE SCHEMA telemetry;
CREATE SEQUENCE telemseq;
CREATE TABLE telemetry.events (
  id INTEGER DEFAULT nextval('telemseq'),
  ts TIMESTAMP, 
  src VARCHAR, 
  host VARCHAR,
  context1 VARCHAR, 
  context1_attrib VARCHAR,
  context2 VARCHAR, 
  context2_attrib VARCHAR,
  context3 VARCHAR, 
  context3_attrib VARCHAR,
  rawevent VARCHAR
);

"#;

#[derive(Deserialize,Debug)]
#[derive(Serialize)]
pub struct EventRecord {
    ts: NaiveDateTime,
    src: String,
    host: String,
    context1: String,
    context1_attrib: String,
    context2: String,
    context2_attrib: String,
    context3: String,
    context3_attrib: String,
    rawevent: String
}

/* 
pub fn initialize_cache(cache_path: &str) -> Result<Connection> {
    let db_exists = std::path::Path::new(cache_path).exists();    
    let conn = Connection::open(cache_path)?;
    
    if !db_exists {
        conn.execute_batch(&CACHE_SCHEMA)?;
    }

    Ok(conn)
}
*/

/*
pub async fn insert_wel_event(conn: &Connection, event: &str) -> Result<()> {
    let now = Utc::now().naive_utc();
    let event_json = serde_json::from_str::<serde_json::Value>(event);
    if event_json.is_err() {
        return Err(duckdb::Error::Execute("Failed to parse event JSON".to_string()));
    }
    let record = EventRecord {
        ts: now,
        src: "WEL".to_string(),
        context1: event_json["Event"]["#c"][0]["System"]["#c"][1]["EventID"]["#t"],
        context1_attrib: "N/A".to_string(),
        context2: "N/A".to_string(),
        context2_attrib: "N/A".to_string(),
        context3: "N/A".to_string(),
        context3_attrib: "N/A".to_string(),
        rawevent: event.to_string()
    };
    insert_event(conn, &record).await
}
 */

/*
pub fn parse_wel_event_draft(json_event: & str) -> Result<(EventRecord), Box<dyn std::error::Error>> {
    let event_json: Value = serde_json::from_str(json_event)?;
    let ts_str = event_json["Event"]["#c"][0]["System"]["#c"][0]["TimeCreated"]["#a"]["SystemTime"]
        .as_str()
        .ok_or("Missing or invalid TimeCreated")?;
    let ts = DateTime::parse_from_rfc3339(ts_str)?.naive_utc();

    let event_id = event_json["Event"]["#c"][0]["System"]["#c"][1]["EventID"]["#t"]
        .as_str()
        .unwrap_or("N/A")
        .to_string();

    let computer = event_json["Event"]["#c"][0]["System"]["#c"][4]["Computer"]["#t"]
        .as_str()
        .unwrap_or("N/A")
        .to_string();

    let provider = event_json["Event"]["#c"][0]["System"]["#c"][2]["Provider"]["#a"]["Name"]
        .as_str()
        .unwrap_or("N/A")
        .to_string();

    let level = event_json["Event"]["#c"][0]["System"]["#c"][3]["Level"]["#t"]
        .as_str()
        .unwrap_or("N/A")
        .to_string();

    Ok(EventRecord {
        ts,
        src: provider,
        context1: event_id,
        context1_attrib: level,
        context2: computer,
        context2_attrib: "N/A".to_string(),
        context3: "N/A".to_string(),
        context3_attrib: "N/A".to_string(),
        rawevent: json_event.to_string(),
    })

}
 */
// TOODO: put somewhere else 
pub fn wel_json_to_er(event_str: &str) -> Result<EventRecord, Box<dyn std::error::Error>> {
    let mut ret  = EventRecord {
        ts: NaiveDateTime::parse_from_str("1970-01-01T00:00:00", "%Y-%m-%dT%H:%M:%S")?,
        src: "WELS".to_string(),
        host: "N/A".to_string(),
        context1: "N/A".to_string(),
        context1_attrib: "N/A".to_string(),
        context2: "N/A".to_string(),
        context2_attrib: "N/A".to_string(),
        context3: "N/A".to_string(),
        context3_attrib: "N/A".to_string(),
        rawevent: event_str.to_string()
    };

    let event_json = serde_json::from_str::<serde_json::Value>(event_str).unwrap();
    //let system_json_array = &str_json["Event"]["#c"][0]["System"]["#c"];
    let system_json_array = &event_json["Event"]["#c"][0]["System"]["#c"];
    let system_json_array = system_json_array.as_array();
    /*
    "Provider"
    "EventID"
    "Version"
    "Level"
    "Task"
    "Opcode"
    "Keywords"
    "TimeCreated"
    "EventRecordID"
    "Correlation"
    "Execution"
    "Channel"
    "Computer"
    "Security" 
    */
    for a in system_json_array.iter() {
        for val in a.iter() {
            for k in val.as_object().expect("INVALID").keys() {
                match k.as_str() {
                    "Channel" => {
                        ret.context1 = val["Channel"]["#a"]["Name"]
                            .as_str()
                            .unwrap_or("N/A")
                            .to_string();
                        ret.context1_attrib = "Channel".to_string();
                    },
                    "Provider" => {
                        ret.context2 = val["Provider"]["#a"]["Name"]
                            .as_str()
                            .unwrap_or("N/A")
                            .to_string();
                        ret.context2_attrib = "Provider".to_string();
                    },
                    "EventID" => {
                        ret.context3 = val["EventID"]["#t"]
                            .as_str()
                            .unwrap_or("N/A")
                            .to_string();
                        ret.context3_attrib = "EID".to_string();
                    },
                    "Computer" => {
                        ret.host = val["Computer"]["#t"]
                            .as_str()
                            .unwrap_or("N/A")
                            .to_string();                        
                    },
                    "TimeCreated" => {
                        let ts_str = val["TimeCreated"]["@SystemTime"].to_string();
                        let ts_str_cleaned = &ts_str.trim_matches('"');
                        let parsed_datetime = DateTime::parse_from_rfc3339(&ts_str_cleaned).expect("1970-01-01T00:00:00").with_timezone(&Utc);
                        let _ = match DateTime::parse_from_rfc3339(&ts_str_cleaned) {
                            Ok(_dt) => {
                                ret.ts = parsed_datetime.naive_utc()
                            },
                            Err(_) => {
                                ret.ts = NaiveDateTime::parse_from_str("1970-01-01T00:00:00", "%Y-%m-%dT%H:%M:%S").unwrap()
                            }
                        };
                        
                    },
                    _ => {}
                }
            }
        }
    }
    Ok(ret)

}
