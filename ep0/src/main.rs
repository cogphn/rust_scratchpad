use futures:: { channel::mpsc::{channel, Receiver}, SinkExt, StreamExt };
use notify::{ Config, Event, RecommendedWatcher,RecursiveMode, Watcher };
use std::path::Path;


fn main() {
    println!("[*] starting...");
    
    let path = std::env::args().nth(1).expect("    [!] path to monitor expected");
    println!("[*] path: {}", path);
    
    futures::executor::block_on(async {
        if let Err(e) = async_watch(path).await {
            println!("    [!][err] {}", e)
        }
    });
}


fn async_watcher() -> notify::Result<(RecommendedWatcher, Receiver<notify::Result<Event>>)> {
    let (mut tx, rx) = channel(1);

    let watcher = RecommendedWatcher::new(
        move |res| {
            futures::executor::block_on(async {
                tx.send(res).await.unwrap();
            })
        },
        Config::default(),
    )?;
    
    Ok((watcher, rx))
}

async fn async_watch<P: AsRef<Path>>(path: P) -> notify::Result<()> {
    let (mut watcher, mut rx) = async_watcher()?;

    watcher.watch(path.as_ref(), RecursiveMode::Recursive)?;

    while let Some(res) = rx.next().await {
        match res {
            Ok(event) => println!(" [*] changed: {:?}", event),
            Err(e) => println!(" [!][err] {:?}", e),
        }
    }

    Ok(())
}
