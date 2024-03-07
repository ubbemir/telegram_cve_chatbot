use crate::logic::nist_api_client::is_valid_cve_string;
use crate::logic::{self, nist_api_structs::CPEResponse, nist_api_client::is_valid_cpe_string};
use crate::persistence;

use std::error::Error;

use frankenstein::AsyncTelegramApi;
use frankenstein::GetUpdatesParams;
use frankenstein::Message;
use frankenstein::SendMessageParams;
use frankenstein::SendPhotoParams;
use frankenstein::SendDocumentParams;
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
        "/start" => was_valid = start_command(params).await,
        "/list_cves" => was_valid = list_cves(&args, params).await,
        "/cve_detail" => was_valid = cve_detail(&args, params).await,
        "/cvss_graph" => was_valid = cvss_graph(&args, params).await,
        "/subscribe" => was_valid = subscribe(&args, params).await,
        "/subscriptions" => was_valid = subscriptions(params).await,
        "/new_cves" => was_valid = new_cves(&args, params).await,
        "/get_pdf" => was_valid = get_pdf(&args, params).await,
        _ => {
            send_msg(&"Invalid command".to_owned(), params).await;
            was_valid = false;
        }
    };

    if was_valid {
        println!("Valid command: {}", command);
    }
}

fn summarize_cpe_response(response: &CPEResponse) -> String {
    let mut msg = String::new();
    for item in &response.vulnerabilities {
        if let Some(severity) = item.cve.get_base_severity() {
            let score: String = match item.cve.get_cvss_base_score() {
                Some(val) => val.to_string(),
                None => "_".to_owned()
            };

            msg.push_str(&format!("{} - {} - {}\n", item.cve.id, severity, score));
            continue;
        }
        
        msg.push_str(&format!("{} - NO METRIC AVAILABLE\n", item.cve.id));
    }

    msg
}

async fn start_command(params: &EventParams<'_>) -> bool {
    send_msg(&format!("Welcome! Begin typing '/' to see available commands.\nTo see their usage just enter the command without any parameters."), params).await;
    true
}

async fn list_cves(args: &Vec<&str>, params: &EventParams<'_>) -> bool {
    if args.len() < 2 {
        send_msg(&format!("Too few arguments. Usage: /list_cves <cpe2.3_string> <OPTIONAL:page_number>"), params).await;
        return false;
    }
    let cpe = args[1];

    if !is_valid_cpe_string(cpe) {
        send_msg(&format!("Invalid CPE string. CPE has to follow CPE2.3 standard"), params).await;
        return false;
    }

    let page = if args.len() >= 3 { args[2].parse::<u64>().unwrap_or(1u64) } else { 1u64 };
    if page < 1 {
        send_msg(&format!("Invalid page number. Page number has to be 1 or greater."), params).await;
        return false;
    }

    send_msg(&format!("Fetching CVEs for CPE (page {}):\n{} ...", page, cpe), params).await;

    let result = logic::interface::list_cves(cpe, page).await;
    if let Err(e) = result {
        send_msg(&format!("Failed to retrieve information from NIST. Error: {}", e), params).await;
        return true;
    }
    let result = result.unwrap();


    let result: CPEResponse = serde_json::from_str(&result).unwrap();
  
    send_msg(&summarize_cpe_response(&result), params).await;

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
        Err(e) => send_msg(&format!("Failed to retrieve subscriptions from DB. Error: {}", e), params).await
    }

    true
}

async fn new_cves(args: &Vec<&str>, params: &EventParams<'_>) -> bool {
    if args.len() < 2 {
        send_msg(&format!("Too few arguments. Usage: /new_cves <days_ago>"), params).await;
        return false;
    }
    
    let days = args[1].parse::<u64>().unwrap_or(7u64);

    send_msg(&format!("Retrieving new CVEs for your subscribed CPEs ..."), params).await;

    let result = logic::interface::new_cves(params.user_id, days).await;

    match result {
        Ok(cpe_responses) => {

            let mut msg = String::new();
            msg.push_str(&format!("Updated CVEs for the latest {} days:\n", days));
            for response in cpe_responses {
                msg.push_str(&format!("{} :\n", response.0));
                msg.push_str(&summarize_cpe_response(&response.1));
                msg.push_str("\n");
            }

            send_msg(&msg, params).await;
        },
        Err(e) => send_msg(&format!("Failed to retrieve new CVEs. Error: {}", e), params).await
    }

    true
}

async fn cve_detail(args: &Vec<&str>, params: &EventParams<'_>) -> bool {
    if args.len() < 2 {
        send_msg(&format!("Too few arguments. Usage: /cve_detail <cve_id>"), params).await;
        return false;
    }
    let cve = args[1];

    if !is_valid_cve_string(cve) {
        send_msg(&format!("Invalid CVE string."), params).await;
        return false;
    }

    send_msg(&format!("Fetching CVE details for {} ...", cve), params).await;

    let result = logic::interface::cve_detail(cve).await;
    if let Err(e) = result {
        send_msg(&format!("Failed to retrieve information from NIST. Error: {}", e), params).await;
        return true;
    }
    let result = result.unwrap();


    let result: CPEResponse = serde_json::from_str(&result).unwrap();

    let mut msg = String::new();
    for item in result.vulnerabilities {
        msg.push_str(&format!("{} :\n\n", item.cve.id));

        // Description
        for desc in &item.cve.descriptions {
            if desc.lang == "en" {
                msg.push_str(&format!("Description: {}\n\n", desc.value));
                break;
            }
        }

        // CVSS
        msg.push_str(&format!("Severity: {}\n", item.cve.get_base_severity().unwrap_or(&"None".to_owned())));

        match item.cve.get_cvss_base_score() {
            Some(score) => msg.push_str(&format!("Base score: {}\n", score.to_string())),
            None => msg.push_str(&format!("Base score unavailable\n"))
        };
        


        // Link
        msg.push_str(&format!("NVD Link: https://nvd.nist.gov/vuln/detail/{}", item.cve.id));
    }
  
    send_msg(&msg, params).await;

    true
}

async fn get_pdf(args: &Vec<&str>, params: &EventParams<'_>) -> bool {
    if args.len() < 2 {
        send_msg(&format!("Too few arguments. Usage: /get_pdf <cpe2.3_string>"), params).await;
        return false;
    }
    let cpe = args[1];

    if !is_valid_cpe_string(cpe) {
        send_msg(&format!("Invalid CPE string. CPE has to follow CPE2.3 standard"), params).await;
        return false;
    }

    send_msg(&format!("Creating PDF report for CPE:\n{} ...", cpe), params).await;

    let pdf_file = logic::interface::get_pdf(cpe, params.chat_id as u64).await;

    match pdf_file {
        Ok(path) => send_file(&path, params).await,
        Err(e) => send_msg(&format!("Failed to create PDF. Error: {}", e), params).await
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

async fn send_file(file_path: &str, params: &EventParams<'_>) {
    let file = std::path::PathBuf::from(file_path);

    let document_params = SendDocumentParams::builder()
        .chat_id(params.chat_id)
        .document(file)
        .build();

    if let Err(error) = params.api.send_document(&document_params).await {
        eprintln!("Failed to upload file: {error:?}");
    }
}