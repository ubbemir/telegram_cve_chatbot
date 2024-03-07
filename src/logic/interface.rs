use crate::persistence;
use crate::persistence::interface::Subscription;

use super::{chart_creator, pdf_creator};
use super::nist_api_client::{is_valid_cpe_string, NISTAPIClient};
use super::nist_api_structs::CPEResponse;

use std::error::Error;
use std::fmt;

#[derive(Debug)]
struct LogicError(String);
unsafe impl Send for LogicError {}
impl fmt::Display for LogicError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "LOGIC_ERROR: {}", self.0)
    }
}
impl Error for LogicError {}

pub async fn list_cves(cpe: &str, page: u64) -> Result<String, Box<dyn Error + Send>> {
    let client = NISTAPIClient::new();
    let response = client.get_cves_from_cpe(cpe, Some(10), Some(page)).await?;

    let result = serde_json::to_string(&response).unwrap();

    Ok(result)
}

pub async fn cvss_chart(arg: &str, id: u64) -> Result<String, Box<dyn Error + Send>> {
    let client = NISTAPIClient::new();
    let response = client.get_cves_from_cpe(arg, None, None).await?;

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

pub async fn new_cves(user_id: u64, days: u64) -> Result<Vec<(String, CPEResponse)>, Box<dyn Error + Send>> {
    let client = NISTAPIClient::new();
    let subs: Vec<Subscription> = serde_json::from_str(&persistence::interface::retrieve_subscriptions(user_id).await?).unwrap_or(Vec::new());

    let now = chrono::Utc::now();
    let present = match now.checked_sub_days(chrono::Days::new(days)) {
        Some(val) => val,
        None => return Err(Box::new(LogicError(format!("Failed to get date {} days ago.", days))))
    };

    let mut result: Vec<(String, CPEResponse)> = Vec::with_capacity(subs.len()); 
    for sub in subs {
        if !is_valid_cpe_string(&sub.cpe) { continue; }

        let response = client.get_latest_updated_cves_from_cpe(&sub.cpe, present.timestamp(), now.timestamp()).await?;

        result.push((sub.cpe, response));
    }

    Ok(result)
}

pub async fn cve_detail(cve: &str) -> Result<String, Box<dyn Error + Send>> {
    let client = NISTAPIClient::new();
    let response = client.get_cve_info(cve).await?;

    let result = serde_json::to_string(&response).unwrap();

    Ok(result)
}

pub async fn get_pdf(cpe: &str, id: u64) -> Result<String, Box<dyn Error + Send>> {
    let client = NISTAPIClient::new();
    let response = client.get_cves_from_cpe(cpe, Some(20), Some(1)).await?;

    let pdf_file = pdf_creator::generate_pdf(id, cpe, response)?;
    Ok(pdf_file)
}