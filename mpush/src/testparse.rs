use serde_json::{Value, Map};
use serde_json::json;





fn get_wel_values(obj: &Map<String, Value>, key: &String, mut parentkey: String) -> Vec<Map<String, Value>>  {
    let val = obj[key].clone();
    parentkey = parentkey.replace("#c\\", "");
    if key == "#t" {
        let mut ret = serde_json::Map::new();
        ret.insert(parentkey, val);
        return vec![ret]; 
    }    
    match &val {
        Value::Object(map) =>  {
            let mut ret = vec![];
            for topkey in map.keys() {
                let mut r1 = get_wel_values(map, topkey, (parentkey.clone() + "\\"+ key).to_string());
                ret.append(&mut r1);
            }
            return ret;
        },
        Value::Array(_arr) =>  {
            if let Some(data_array) = val.as_array() {
                let mut ret = vec![];
                for a in data_array{
                    match a {
                        Value::Object(ar_obj) => {
                            for topkey in ar_obj.keys() {
                                let mut r1 = get_wel_values(ar_obj, topkey, (parentkey.clone() + "\\"+ key).to_string());
                                ret.append(&mut r1);
                            }
                        },                        
                        Value::String(str) => {                            
                            let mut r1 = Map::new();
                            //r1[&parentkey] = json!(str); //this is probably wrong
                            r1.insert(parentkey.clone(), json!(str));
                            ret.append(&mut vec![r1]);
                        },
                        Value::Null => {},
                        _ => {
                            println!("[!] TODO: match more types");
                        }
                    }
                }
                return ret;
            } else {
                return vec![]; // maybe this never happens
            }
        },
        Value::String(str) => {
            let mut r1 = serde_json::Map::new();
            let v = json!(str);            
            r1.insert(key.to_string(), v);
            return vec![r1];

        },
        _ => {
            println!("[!]: match more values here ");
            return vec![];
        }
    }    
}

fn wel_raw_to_obj(wels_raw: String) -> Result<serde_json::Map<String, Value>, serde_json::Error> {
    let wels_obj: Result<serde_json::Value, serde_json::Error> = serde_json::from_str(&wels_raw);

    let obj = match wels_obj {
        Err(e) => {
            return Err(e);
        },
        Ok(val) => {val}
    };
    
    let mut ret = serde_json::Map::new();

    if let Value::Object(map) = &obj["Event"] {
        for topkey in map.keys() {
            let x = get_wel_values(map, topkey, "<root>".to_string());
            let mut kresolver = 1;
            for obj in x.clone().into_iter() {
                for k in obj.keys() {
                    if obj[k] == "(NULL)"{
                        continue;
                    }                        
                    if k.starts_with("<root>\\System") {                        
                        let mut nk =k.replace("<root>\\System\\", "");
                        nk = nk.replace("@","");
                        ret.insert(nk, obj[k].clone());
                    } else {
                        let mut nk = k.replace("<root>\\","");
                        nk = nk.replace("@", "");
                        if ret.contains_key(&nk) {                            
                            nk = nk + &kresolver.to_string();
                            kresolver += 1;                            
                        }
                        ret.insert(nk, obj[k].clone());
                        
                    }                    
                }
            }
        }
    }


    Ok(ret)

}



fn main() {
    

    let x = r###"{
    "Event": {
        "#c": [
            {
                "System": {
                    "#c": [
                        {
                            "Provider": {
                                "@Name": "MsiInstaller"
                            }
                        },
                        {
                            "EventID": {
                                "#t": "11729",
                                "@Qualifiers": "0"
                            }
                        },
                        {
                            "Version": {
                                "#t": "0"
                            }
                        },
                        {
                            "Level": {
                                "#t": "4"
                            }
                        },
                        {
                            "Task": {
                                "#t": "0"
                            }
                        },
                        {
                            "Opcode": {
                                "#t": "0"
                            }
                        },
                        {
                            "Keywords": {
                                "#t": "0x80000000000000"
                            }
                        },
                        {
                            "TimeCreated": {
                                "@SystemTime": "2025-10-29T01:06:13.2482484Z"
                            }
                        },
                        {
                            "EventRecordID": {
                                "#t": "109003"
                            }
                        },
                        {
                            "Correlation": {}
                        },
                        {
                            "Execution": {
                                "@ProcessID": "0",
                                "@ThreadID": "0"
                            }
                        },
                        {
                            "Channel": {
                                "#t": "Application"
                            }
                        },
                        {
                            "Computer": {
                                "#t": "labhost2"
                            }
                        },
                        {
                            "Security": {
                                "@UserID": "S-1-5-21-3338565303-3805897153-2758210402-1001"
                            }
                        }
                    ]
                }
            },
            {
                "EventData": {
                    "#c": [
                        {
                            "Data": {
                                "#t": "Product: Oracle VirtualBox 7.1.4 -- Configuration failed."
                            }
                        },
                        {
                            "Data": {
                                "#t": "(NULL)"
                            }
                        },
                        {
                            "Data": {
                                "#t": "(NULL)"
                            }
                        },
                        {
                            "Data": {
                                "#t": "(NULL)"
                            }
                        },
                        {
                            "Data": {
                                "#t": "(NULL)"
                            }
                        },
                        {
                            "Data": {
                                "#t": "(NULL)"
                            }
                        },
                        {
                            "Data": {}
                        },
                        {
                            "Binary": {
                                "#t": "7B42374545394142322D343138382D344235462D383439392D3433313134453741443744417D2C2031363032"
                            }
                        }
                    ]
                }
            }
        ],
        "@xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"
    }
}"###;
    

    let x = wel_raw_to_obj(x.to_string());
    

    match x {
        Err(e) => {
            println!("[!] error occured: {:?}", e);
        },
        Ok(v) => {
            println!("[✓] parsed");
            let z = serde_json::to_string(&v);
            match z {
                Err(e) => {
                    println!("[!] error converting object to string: {:?} ", e);
                },
                Ok(str) => {
                    println!("{}", str);
                }
            }
        }
    }    
    println!("[.] done! ");
    
}