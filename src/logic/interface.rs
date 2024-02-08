use super::nist_api_client::NISTAPIClient;

pub async fn list_cves(arg: &str) -> String {
    let client = NISTAPIClient::new();
    let response = client.get_cves_from_cpe(arg.to_owned(), 10).await.unwrap();

    let result = serde_json::to_string(&response).unwrap();

    result
}