use crate::logic::{self, nist_api_structs::CPEResponse, nist_api_client::is_valid_cpe_string};
use crate::persistence;

use std::error::Error;

use frankenstein::AsyncTelegramApi;
use frankenstein::GetUpdatesParams;
use frankenstein::Message;
use frankenstein::SendMessageParams;
use frankenstein::SendPhotoParams;
use frankenstein::{AsyncApi, UpdateContent};

struct EventParams <'a> {
    user_id: u64,
    chat_id: i64,
    api: &'a AsyncApi
}

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
    let params = EventParams { 
        user_id: from.id,
        chat_id: message.chat.id,
        api: &api
    };

    parse_user_input(&msg, &params).await;
}

async fn parse_user_input(line: &str, params: &EventParams<'_>) {
    let args: Vec<&str> = line.split(" ").collect();
    let command = args[0];

    let was_valid;
    match command {
        "/list_cves" => was_valid = list_cves(&args, params).await,
        "/cvss_graph" => was_valid = cvss_graph(&args, params).await,
        "/subscribe" => was_valid = subscribe(&args, params).await,
        "/subscriptions" => was_valid = subscriptions(params).await,
        _ => {
            send_msg(&"Invalid command".to_owned(), params).await;
            was_valid = false;
        }
    };

    if was_valid {
        println!("Valid command: {}", command);
    }
}

async fn list_cves(args: &Vec<&str>, params: &EventParams<'_>) -> bool {
    if args.len() < 2 {
        send_msg(&format!("Too few arguments. Usage: /list_cves <cpe2.3_string>"), params).await;
        return false;
    }
    let cpe = args[1];

    if !is_valid_cpe_string(cpe) {
        send_msg(&format!("Invalid CPE string. CPE has to follow CPE2.3 standard"), params).await;
        return false;
    }

    send_msg(&format!("Fetching CVEs for CPE:\n{} ...", cpe), params).await;

    let result = logic::interface::list_cves(cpe).await;
    if let Err(e) = result {
        send_msg(&format!("Failed to retrieve information from NIST. Error: {}", e), params).await;
        return true;
    }
    let result = result.unwrap();


    let result: CPEResponse = serde_json::from_str(&result).unwrap();

    let mut msg = String::new();
    for item in result.vulnerabilities {
        if let Some(severity) = item.cve.get_base_severity() {
            msg.push_str(&format!("{} - {}\n", item.cve.id, severity));
            continue;
        }
        
        msg.push_str(&format!("{} - NO METRIC AVAILABLE\n", item.cve.id));
    }
  
    send_msg(&msg, params).await;

    true
}

async fn cvss_graph(args: &Vec<&str>, params: &EventParams<'_>) -> bool {
    if args.len() < 2 {
        send_msg(&format!("Too few arguments. Usage: /cvss_graph <cpe2.3_string>"), params).await;
        return false;
    }
    let cpe = args[1];

    if !is_valid_cpe_string(cpe) {
        send_msg(&format!("Invalid CPE string. CPE has to follow CPE2.3 standard"), params).await;
        return false;
    }

    send_msg(&format!("Creating CVSS score graph for CPE:\n{} ...", cpe), params).await;

    let cvss_chart = logic::interface::cvss_chart(cpe, params.chat_id as u64).await;

    match cvss_chart {
        Ok(path) => send_photo(&path, params).await,
        Err(e) => send_msg(&format!("Failed to create graph. Error: {}", e), params).await
    }

    true
}

async fn subscribe(args: &Vec<&str>, params: &EventParams<'_>) -> bool {
    if args.len() < 2 {
        send_msg(&format!("Too few arguments. Usage: /subscribe <cpe2.3_string>"), params).await;
        return false;
    }
    let cpe = args[1];

    if !is_valid_cpe_string(cpe) {
        send_msg(&format!("Invalid CPE string. CPE has to follow CPE2.3 standard"), params).await;
        return false;
    }

    send_msg(&format!("Adding your subscription of CPE={} ...", cpe), params).await;

    let result = persistence::interface::add_subscription(cpe, params.user_id).await;

    match result {
        Ok(_) => send_msg(&format!("Subscription successfully added!"), params).await,
        Err(e) => send_msg(&format!("Failed to insert subscription to DB. Error: {}", e), params).await
    }

    true
}

async fn subscriptions(params: &EventParams<'_>) -> bool {
    send_msg(&format!("Retrieving your subscribed CPEs ..."), params).await;

    let result = persistence::interface::retrieve_subscriptions(params.user_id).await;

    match result {
        Ok(result) => {
            let subs: Vec<persistence::interface::Subscription> = serde_json::from_str(&result).expect("Invalid JSON recieved from persistence layer!");

            let mut msg = String::new();
            msg.push_str("Your subsrcibed CPEs:\n");
            for sub in subs {
                msg.push_str(&format!("{}\n", sub.cpe));
            }

            send_msg(&msg, params).await;
        },
        Err(e) => send_msg(&format!("Failed to insert subscription to DB. Error: {}", e), params).await
    }

    true
}

async fn send_msg(msg: &str, params: &EventParams<'_>) {
    let send_message_params = SendMessageParams::builder()
        .chat_id(params.chat_id)
        .text(msg)
        .build();

    if let Err(err) = params.api.send_message(&send_message_params).await {
        eprintln!("Failed to send message: {err:?}");
    }
}

async fn send_photo(photo_path: &str, params: &EventParams<'_>) {
    let file = std::path::PathBuf::from(photo_path);

    let photo_params = SendPhotoParams::builder()
        .chat_id(params.chat_id)
        .photo(file)
        .build();

    if let Err(error) = params.api.send_photo(&photo_params).await {
        eprintln!("Failed to upload photo: {error:?}");
    }
}