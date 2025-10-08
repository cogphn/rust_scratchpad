use rocket::{get, launch, routes};
use rocket::fs::{FileServer, relative};


#[macro_use] extern crate rocket;

#[get("/")]
fn index() -> &'static str {
    "[*] running..."
}

#[get("/obs")]
fn obs() -> &'static str {
    "[*] running..."
}

#[launch]
fn rocket() -> _ {
    rocket::build()
    .mount("/", routes![index])
    .mount("/", routes![obs])
    .mount("/static", FileServer::from(relative!("static")))
}
