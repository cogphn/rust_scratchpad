use std::string::FromUtf8Error;

use quick_xml_to_json::xml_to_json;


pub fn evt_xml_to_json(xml: String) -> Result<String, FromUtf8Error> {
    let mut ret = Vec::new();
    let _ = xml_to_json(xml.as_bytes(), &mut ret);
    let json_str = String::from_utf8(ret);
    return json_str;
}
