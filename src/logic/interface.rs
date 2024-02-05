use super::nist_api_client::NISTAPIClient;

pub async fn list_cves(arg: &str) -> String {
    let client = NISTAPIClient::new();
    let response = client.get_cves_from_cpe(arg.to_owned()).await.unwrap();

    let mut result = String::new();
    for item in response {
        result.push_str(&serde_json::to_string(&item).unwrap());
    }

    result
}