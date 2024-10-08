use tokio::runtime::Builder;
use std::error::Error;
use std::fs;
use std::env;

pub mod logic;
pub mod presentation;
pub mod persistence;

use presentation::telegram;

const CONFIG_FILE_NAME: &str = "bot_config.json";

fn get_config_path() -> String {
    let mut exe_path = env::current_exe().unwrap();
    let _ = exe_path.pop();
    exe_path.push(&CONFIG_FILE_NAME);
    exe_path.to_str().unwrap().to_string()
}

fn create_dir_if_not_exists(dir_name: &str) -> std::io::Result<()> {
    let mut path = env::current_exe().unwrap();
    let _ = path.pop();
    path.push(dir_name);

    fs::create_dir_all(&path)?;

    Ok(())
}

async fn root() -> Result<(), Box<dyn Error>> {
    let config_path = get_config_path();
    let contents = fs::read_to_string(&config_path)
        .expect(&format!("{} not found!", &config_path));

    let parsed_config: serde_json::Value = serde_json::from_str(&contents).expect(&format!("Invalid JSON in {}", &config_path));
    let token = parsed_config["token"].as_str().expect("Failed to extract bot token").to_owned().clone();

    create_dir_if_not_exists("cvss_charts").expect("Failed to create cvss_charts directory");
    create_dir_if_not_exists("pdf").expect("Failed to create pdf directory");

    persistence::interface::initialize_db().await;

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