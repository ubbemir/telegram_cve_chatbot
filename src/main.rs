use tokio::runtime::Builder;
use std::error::Error;

pub mod logic;
pub mod presentation;

use presentation::console;


async fn root() -> Result<(), Box<dyn Error>> {
    let join_handle = tokio::spawn(async move {
        console::event_loop().await;
    });

    let _ = join_handle.await;

    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    let runtime = Builder::new_multi_thread()
                .enable_all()
                .build()
                .unwrap();

    runtime.block_on(root())
}