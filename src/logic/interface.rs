use super::nist_api_client::NISTAPIClient;
use std::error::Error;

pub async fn list_cves(arg: &str) -> Result<String, Box<dyn Error + Send>> {
    let client = NISTAPIClient::new();
    let response = client.get_cves_from_cpe(arg.to_owned(), true, 10).await;
    if let Err(e) = response {
        return Err(e);
    }
    let response = response.unwrap();
    let result = serde_json::to_string(&response).unwrap();

    Ok(result)
}