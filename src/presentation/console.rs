use crate::logic::{self, nist_api_structs::CPEResponse};

pub async fn event_loop() {
    loop {
        let mut line = String::new();
        println!("Enter a command:");
        std::io::stdin().read_line(&mut line).unwrap();
        parse_user_input(&line).await;
    }
}

async fn parse_user_input(line: &String) {
    let (command, args) = line.split_once(" ").unwrap_or(("", ""));
    let args = args.trim();

    match command {
        "/list_cves" => list_cves(&args).await,
        _ => println!("Invalid command!")
    };
}

async fn list_cves(args: &str) {
    println!("Fetching CVEs for cpe={} ...", args);

    let result = logic::interface::list_cves(&args, 1).await.unwrap();
    let result: CPEResponse = serde_json::from_str(&result).unwrap();

    for item in result.vulnerabilities {
        println!("{}", item.cve.id);
    }
}