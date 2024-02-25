use crate::logic::chart_creator;

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

pub async fn cvss_chart(arg: &str) -> Result<String, Box<dyn Error + Send>> {
    let client = NISTAPIClient::new();
    let response = client.get_cves_from_cpe(arg.to_owned(), false, 0).await;
    if let Err(e) = response {
        return Err(e);
    }
    let response = response.unwrap();

    let mut cvss_count = vec![("Low", 0u64), ("Medium", 0u64), ("High", 0u64), ("Critical", 0u64)];
    for item in response.vulnerabilities {
        if let Some(severity) = item.cve.get_base_severity() {
            match severity.to_lowercase().as_str() {
                "low" => cvss_count[0].1 += 1,
                "medium" => cvss_count[1].1 += 1,
                "high" => cvss_count[2].1 += 1,
                "critical" => cvss_count[3].1 += 1,
                _ => ()
            }
        }
    }
    
    let chart_file = chart_creator::create_cvss_chart(10, cvss_count)?;
    Ok(chart_file)
}