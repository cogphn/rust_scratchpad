use std::env;
use std::fs;
use regex::Regex;

use std::collections::HashSet;



pub fn main(){

    println!("[*] Starting...");

    let args: Vec<String> = env::args().collect();

    if args.len() < 2{
        println!("    [!] Invalid arguments");
        println!("[!] Finished with errors");
        std::process::exit(1);
    }

    let filename : &str = &args[1];
    let text = fs::read_to_string(filename).expect("    [!] unable to read file");


    let ip_re : regex::Regex = Regex::new(r"\b(?:\d{1,3}\.){3}\d{1,3}\b").unwrap();
    let md5_re : regex::Regex  = Regex::new(r"\b[a-fA-F0-9]{32}\b").unwrap();
    let sha1_re : regex::Regex  = Regex::new(r"\b[a-fA-F0-9]{40}\b").unwrap();
    let sha256_re : regex::Regex  = Regex::new(r"\b[a-fA-F0-9]{64}\b").unwrap();
    let domain_re : regex::Regex  = Regex::new(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b").unwrap();
    let email_re : regex::Regex = Regex::new(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b").unwrap();


    let mut ip_results: Vec<_> = ip_re.find_iter(&text).map(|m| m.as_str()).collect();
    let mut domain_results: Vec<_> = domain_re.find_iter(&text).map(|m| m.as_str()).collect();
    let mut sha1_results: Vec<_> = sha1_re.find_iter(&text).map(|m| m.as_str()).collect();
    let mut sha256_results: Vec<_> = sha256_re.find_iter(&text).map(|m| m.as_str()).collect();
    let mut md5_results: Vec<_> = md5_re.find_iter(&text).map(|m| m.as_str()).collect();
    let mut email_results: Vec<_> = email_re.find_iter(&text).map(|m| m.as_str()).collect();

    let mut set: HashSet<_> = domain_results.drain(..).collect();
    domain_results.extend(set.into_iter());
    
    set = ip_results.drain(..).collect();
    ip_results.extend(set.into_iter());
    
    set = sha1_results.drain(..).collect();
    sha1_results.extend(set.into_iter());
    
    set = sha256_results.drain(..).collect();
    sha256_results.extend(set.into_iter());
    
    set = email_results.drain(..).collect();
    email_results.extend(set.into_iter());

    set = md5_results.drain(..).collect();
    md5_results.extend(set.into_iter());

    println!("{:?}, {:?}, {:?}, {:?}, {:?}, {:?}", ip_results, domain_results, sha1_results, sha256_results, md5_results, email_results);
    println!("[.] Done!");
}
