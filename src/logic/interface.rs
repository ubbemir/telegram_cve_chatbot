use super::chart_creator;
use super::nist_api_client::NISTAPIClient;

use std::error::Error;

pub async fn list_cves(cpe: &str, page: u64) -> Result<String, Box<dyn Error + Send>> {
    let client = NISTAPIClient::new();
    let response = client.get_cves_from_cpe(cpe.to_owned(), Some(10), Some(page)).await?;

    let result = serde_json::to_string(&response).unwrap();

    Ok(result)
}

pub async fn cvss_chart(arg: &str, id: u64) -> Result<String, Box<dyn Error + Send>> {
    let client = NISTAPIClient::new();
    let response = client.get_cves_from_cpe(arg.to_owned(), None, None).await?;

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

    let chart_file = chart_creator::create_cvss_chart(id, cvss_count)?;
    Ok(chart_file)
}