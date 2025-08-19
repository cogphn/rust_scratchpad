//use std::env;
use std::fs;
use regex::Regex;
use std::io::Write;
use std::fs::File;

use std::collections::HashSet;
use clap::Parser;


#[derive(Parser)]
struct Cli {
    infile: std::path::PathBuf,
    outfile: std::path::PathBuf
}


#[derive(Debug, PartialEq, Eq, Hash)]
struct Observable {
    observable: String,
    obs_type: String
}

pub fn main() {


    let args = Cli::parse();

    let infile = args.infile;
    let outfile = args.outfile;

    let filename : &str = &infile.into_os_string().into_string().unwrap();
    let outfile_str : &str = &outfile.into_os_string().into_string().unwrap();


    let text = fs::read_to_string(filename).expect("    [!] unable to read file");
    
    println!("[*] Running...");


    let ip_re : regex::Regex = Regex::new(r"\b(?:\d{1,3}\.){3}\d{1,3}\b").unwrap();
    let md5_re : regex::Regex  = Regex::new(r"\b[a-fA-F0-9]{32}\b").unwrap();
    let sha1_re : regex::Regex  = Regex::new(r"\b[a-fA-F0-9]{40}\b").unwrap();
    let sha256_re : regex::Regex  = Regex::new(r"\b[a-fA-F0-9]{64}\b").unwrap();
    let domain_re : regex::Regex  = Regex::new(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b").unwrap();
    let email_re : regex::Regex = Regex::new(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b").unwrap();
    let url_re : regex::Regex = Regex::new(r"https?://\S+").unwrap();

    let mut label = "ipv4";
    let ip_results: Vec<_> = ip_re.find_iter(&text).map(|m| { label = "ipv4"; Observable { observable: m.as_str().to_string(), obs_type: label.to_string() } }).collect();
    let domain_results: Vec<_> = domain_re.find_iter(&text).map(|m| { label = "domain"; Observable { observable: m.as_str().to_string(), obs_type: label.to_string() } }).collect();
    let sha1_results: Vec<_> = sha1_re.find_iter(&text).map(|m| { label = "sha1"; Observable { observable: m.as_str().to_string(), obs_type: label.to_string() } }).collect();
    let sha256_results: Vec<_> = sha256_re.find_iter(&text).map(|m| { label = "sha256"; Observable { observable: m.as_str().to_string(), obs_type: label.to_string() } }).collect();
    let md5_results: Vec<_> = md5_re.find_iter(&text).map(|m| { label = "md5"; Observable { observable: m.as_str().to_string(), obs_type: label.to_string() } }).collect();
    let email_results: Vec<_> = email_re.find_iter(&text).map(|m| { label = "email"; Observable { observable: m.as_str().to_string(), obs_type: label.to_string() } }).collect();
    let url_results : Vec<_> = url_re.find_iter(&text).map(|m| { label = "url"; Observable { observable: m.as_str().to_string(), obs_type: label.to_string() } }).collect();

    let unique_ip_addrs: HashSet<_> = ip_results.into_iter().collect();
    let unique_domain: HashSet<_> = domain_results.into_iter().collect();
    let unique_sha1: HashSet<_> = sha1_results.into_iter().collect();
    let unique_sha256: HashSet<_> = sha256_results.into_iter().collect();
    let unique_email: HashSet<_> = email_results.into_iter().collect();
    let unique_md5: HashSet<_> = md5_results.into_iter().collect();
    let unique_url: HashSet<_> = url_results.into_iter().collect();

    let mut all_observables = Vec::new();
    all_observables.extend(unique_ip_addrs);
    all_observables.extend(unique_domain);
    all_observables.extend(unique_sha1);
    all_observables.extend(unique_sha256);
    all_observables.extend(unique_email);
    all_observables.extend(unique_md5);
    all_observables.extend(unique_url);


    println!("    [*] writing results to {:?}", outfile_str);
    let mut file = match File::create(outfile_str) {
        Ok(f) => f,
        Err(error) => {
            println!("    [!] cannot open output file {:?}", error);
            std::process::exit(1);
        }
    };

    match writeln!(file, "observable,type") {
        Ok(res) => res,
        Err(error) => {
            println!("    [!] error writing header to output file: {:?}", error);
        }
    };
    for obs in all_observables {
        match writeln!(file,"{},{}", obs.observable, obs.obs_type){
            Ok(res) => res,
            Err(error) => {
                println!("    [!] error writing data to output file: {:?}", error);
            }
        };
    }
    
    println!("[.] Done!");
}
