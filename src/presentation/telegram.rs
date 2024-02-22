use crate::logic::{self, nist_api_client::CPEResponse};

use std::error::Error;

use frankenstein::AsyncTelegramApi;
use frankenstein::GetUpdatesParams;
use frankenstein::Message;
use frankenstein::SendMessageParams;
use frankenstein::{AsyncApi, UpdateContent};

pub async fn event_loop(token: &str) -> Result<&'static str, Box<dyn Error + Send>> {
    let api = AsyncApi::new(token);
    
    match api.get_me().await {
        Ok(response) => {
            let user = response.result;
            println!(
                "Telegram bot started, found at: @{}, https://t.me/{}",
                user.first_name,
                user.username.expect("The bot must have a username.")
            );
        }
        Err(error) => {
            eprintln!("Failed to get me: {error:?}");
            return Err(Box::new(error));
        }
    }

    let update_params_builder = GetUpdatesParams::builder();
    let mut update_params = update_params_builder.clone().build();
    loop {
        let result = api.get_updates(&update_params).await;

        match result {
            Ok(response) => {
                for update in response.result {
                    if let UpdateContent::Message(message) = update.content {
                        let api_clone = api.clone();

                        tokio::spawn(async move {
                            process_message(message, api_clone).await;
                        });
                    }
                    update_params = update_params_builder
                        .clone()
                        .offset(update.update_id + 1)
                        .build();
                }
            }
            Err(error) => {
                eprintln!("Failed to get updates: {error:?}");
            }
        }
    }
}

async fn process_message(message: Message, api: AsyncApi) {
    if message.from.is_none() { return; }
    let from = message.from.unwrap();

    if from.is_bot { return; }

    let msg = message.text.unwrap_or("[UNKOWN MESSAGE]".to_owned());

    parse_user_input(&msg, message.chat.id, &api).await;
}

async fn parse_user_input(line: &str, chatid: i64, api: &AsyncApi) {
    let (command, args) = line.split_once(" ").unwrap_or(("", ""));
    let args = args.trim();

    match command {
        "/list_cves" => list_cves(&args, chatid, api).await,
        _ => send_msg(&"Invalid command".to_owned(), chatid, api).await
    };
}

async fn list_cves(args: &str, chatid: i64, api: &AsyncApi) {
    send_msg(&format!("Fetching CVEs for CPE:\n{} ...", args), chatid, api).await;

    let result = logic::interface::list_cves(&args).await;
    if let Err(e) = result {
        send_msg(&format!("Failed to retrieve information from NIST, possible that you provided an invalid CPE string. Error: {}", e), chatid, api).await;
        return;
    }
    let result = result.unwrap();


    let result: CPEResponse = serde_json::from_str(&result).unwrap();

    let mut msg = String::new();
    for item in result.vulnerabilities {
        match item.cve.metrics.cvssMetricV2 {
            Some(metrics) => msg.push_str(&format!("{} - {}\n", item.cve.id, metrics[0].baseSeverity)),
            _ => msg.push_str(&format!("{} - NO METRIC AVAILABLE\n", item.cve.id))
        }
    }
    send_msg(&msg, chatid, api).await;
}

async fn send_msg(msg: &str, chatid: i64, api: &AsyncApi) {
    let send_message_params = SendMessageParams::builder()
        .chat_id(chatid)
        .text(msg)
        .build();

    if let Err(err) = api.send_message(&send_message_params).await {
        println!("Failed to send message: {err:?}");
    }
}