const BASE_URL: &str = "https://services.nvd.nist.gov/rest/json/cves/2.0";

use std::{error::Error, fmt, sync::Arc};
use serde::{Serialize, Deserialize};

#[derive(Deserialize)]
#[allow(non_snake_case)]
pub struct CPEResponse {
    pub vulnerabilities: Vec<CVEContainer>
}

#[derive(Serialize, Deserialize)]
#[allow(non_snake_case)]
pub struct CVEContainer {
    pub cve: CVE
}

#[derive(Serialize, Deserialize)]
#[allow(non_snake_case)]
pub struct CVE {
    pub id: String,
    pub sourceIdentifier: String,
    pub published: String,
    pub lastModified: String,
    pub vulnStatus: String,
    pub descriptions: Vec<CVEDetail>,
    // pub metrics: serde_json::Value

}

#[derive(Serialize, Deserialize)]
#[allow(non_snake_case)]
pub struct CVEDetail {
    pub lang: String,
    pub value: String
}

#[derive(Serialize, Deserialize)]
#[allow(non_snake_case)]
pub struct CVSSMetricV2Container {
    pub cvssMetricV2: Vec<CVSSMetricV2>
    
}

#[derive(Serialize, Deserialize)]
#[allow(non_snake_case)]
pub struct CVSSMetricV2 {
    pub source: String,
    
}

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

    pub async fn get_cves_from_cpe(&self, cpe: String) -> Result<Vec<CVEContainer>, Box<dyn Error + Send>> {
        let url = format!("{}?cpeName={}", BASE_URL, urlencoding::encode(&cpe));
        
        let response = self.http_client.get(&url).send().await;
    
        let response = match response {
            Ok(res) => res,
            Err(_) => return Err(Box::new(NISTApiError("API endpoint not responding".into())))
        };
        if !response.status().is_success() {
            return Err(Box::new(NISTApiError("API endpoint refused".into())));
        }
        
        let response: CPEResponse = match response.json::<CPEResponse>().await {
            Ok(res) => res,
            Err(_) => return Err(Box::new(NISTApiError("Failed to parse response as json".into())))
        };
        
        Ok(response.vulnerabilities)
    }
}