const BASE_URL: &str = "https://services.nvd.nist.gov/rest/json/cves/2.0";

use std::{error::Error, fmt, sync::Arc};
use super::nist_api_structs::*;

#[derive(Debug)]
struct NISTApiError(String);
unsafe impl Send for NISTApiError {}
impl fmt::Display for NISTApiError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "NIST_API_ERROR: {}", self.0)
    }
}
impl Error for NISTApiError {}

#[derive(Clone)]
pub struct NISTAPIClient {
    http_client: Arc<reqwest::Client>
}

impl NISTAPIClient {
    pub fn new() -> NISTAPIClient {
        NISTAPIClient {
            http_client: Arc::new(reqwest::Client::new())
        }
    }

    async fn query_nist(&self, params: String) -> Result<CPEResponse, Box<dyn Error + Send>> {
        let url = format!("{}?{}", BASE_URL, params);

        let response = self.http_client.get(&url).send().await;
    
        let response = match response {
            Ok(res) => res,
            Err(_) => return Err(Box::new(NISTApiError("API endpoint not responding".into())))
        };
        if !response.status().is_success() {
            return Err(Box::new(NISTApiError(format!("API endpoint refused: Code {}", response.status()))));
        }
        
        let response: CPEResponse = match response.json::<CPEResponse>().await {
            Ok(res) => res,
            Err(_) => return Err(Box::new(NISTApiError("Failed to parse response as json".into())))
        };

        Ok(response)
    }

    pub async fn get_cves_from_cpe(&self, cpe: String, limited_results: bool, amount: u64) -> Result<CPEResponse, Box<dyn Error + Send>> {
        if !limited_results {
            let params = format!("cpeName={}", urlencoding::encode(&cpe));
            let response = self.query_nist(params).await?;

            return Ok(response);
        }
        
        // this first request is used to get the total amount of CVEs
        let params = format!("cpeName={}&resultsPerPage=1", urlencoding::encode(&cpe));
        let response = self.query_nist(params).await?;

        let mut start_index = 0;
        if amount < response.totalResults {
            start_index = response.totalResults - amount;    
        }
        
        let params = format!("cpeName={}&resultsPerPage={}&startIndex={}", urlencoding::encode(&cpe), amount, start_index);
        let response = self.query_nist(params).await?;

        Ok(response)
    }
}


#[cfg(test)]
mod unit_tests {
    use super::CVE;

    const TEST_FILES_DIR: &str = "tests/json_input";

    #[test]
    fn cvss_v31_test() {
        let mut d = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        d.push(TEST_FILES_DIR);
        d.push("cvss_v31.json");

        let contents = std::fs::read_to_string(&d)
        .expect(&format!("{:?} not found!", d));

        let input: CVE = serde_json::from_str(&contents).expect("Failed to parse input JSON as CVE");

        assert_eq!(input.get_base_severity().unwrap(), "HIGH");
    }

    #[test]
    fn cvss_v2_test() {
        let mut d = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        d.push(TEST_FILES_DIR);
        d.push("cvss_v2.json");

        let contents = std::fs::read_to_string(&d)
        .expect(&format!("{:?} not found!", d));

        let input: CVE = serde_json::from_str(&contents).expect("Failed to parse input JSON as CVE");

        assert_eq!(input.get_base_severity().unwrap(), "MEDIUM");
    }

    #[test]
    fn invalid_cvss_version_test() {
        let mut d = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        d.push(TEST_FILES_DIR);
        d.push("invalid_cvss_version.json");

        let contents = std::fs::read_to_string(&d)
        .expect(&format!("{:?} not found!", d));

        let input: CVE = serde_json::from_str(&contents).expect("Failed to parse input JSON as CVE");

        assert_eq!(input.get_base_severity(), None);
    }
}