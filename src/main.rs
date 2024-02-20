use tokio::runtime::Builder;
use std::error::Error;
use std::fs;
use std::env;

pub mod logic;
pub mod presentation;

use presentation::telegram;

const CONFIG_FILE_NAME: &str = "bot_config.json";

fn get_config_path() -> String {
    let mut exe_path = env::current_exe().unwrap();
    let _ = exe_path.pop();
    let exe_path = exe_path.join(&CONFIG_FILE_NAME);
    exe_path.to_str().unwrap().to_string()
}

async fn root() -> Result<(), Box<dyn Error>> {
    let config_path = get_config_path();
    let contents = fs::read_to_string(&config_path)
        .expect(&format!("{} not found!", &config_path));

    let parsed_config: serde_json::Value = serde_json::from_str(&contents).expect(&format!("Invalid JSON in {}", &config_path));
    let token = parsed_config["token"].as_str().expect("Failed to extract bot token").to_owned().clone();

    let join_handle = tokio::spawn(async move {
        let _ = telegram::event_loop(&token).await;
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