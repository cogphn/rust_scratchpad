use tokio::net::TcpListener;
use std::io;




async fn process_socket<T>(_socket: T) {
    println!("[!] called!");
}


#[tokio::main]
async fn main() -> io::Result<()> {

    let srvsocket = TcpListener::bind("0.0.0.0:2005").await?;

    println!("[*] starting server...");

    loop {
        let (socket, _) = srvsocket.accept().await?;
        process_socket(socket).await;
    }

}
