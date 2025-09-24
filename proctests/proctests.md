
<< WIP >>

 - TODO:
   - fix obvi...

### Cargo.toml
~~~toml
[package]
name = "cmdhooktest"
version = "0.1.0"
edition = "2024"

[dependencies]
user32-sys = "0.2.0"
winapi = "0.3.9"
~~~

### main.rs
~~~rust
extern crate user32;
extern crate winapi;


fn main() {
    println!("[*] starting...");

    println!("[.] done.");

}
~~~
