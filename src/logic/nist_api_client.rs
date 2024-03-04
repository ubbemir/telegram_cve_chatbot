const BASE_URL: &str = "https://services.nvd.nist.gov/rest/json/cves/2.0";

use std::{error::Error, fmt, sync::Arc};
use super::nist_api_structs::*;
use regex::Regex;

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

pub fn is_valid_cpe_string(cpe: &str) -> bool {
    let re = Regex::new(r###"cpe:2\.3:[aho\*\-](:(((\?*|\*?)([a-zA-Z0-9\-\._]|(\\[\\\*\?!"#$$%&'\(\)\+,/:;<=>@\[\]\^`\{\|}~]))+(\?*|\*?))|[\*\-])){5}(:(([a-zA-Z]{2,3}(-([a-zA-Z]{2}|[0-9]{3}))?)|[\*\-]))(:(((\?*|\*?)([a-zA-Z0-9\-\._]|(\\[\\\*\?!"#$$%&'\(\)\+,/:;<=>@\[\]\^`\{\|}~]))+(\?*|\*?))|[\*\-])){4}"###).unwrap();
    return re.is_match(cpe);
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
    use super::is_valid_cpe_string;

    #[test]
    fn is_valid_cpe_string_test() {
        assert_eq!(is_valid_cpe_string("test123"), false);
        assert_eq!(is_valid_cpe_string("cpe:2.3:a:alawarmotor_town\\:_machine_soul_free:1.1:*:*:*:*:android:*:*"), false); // looks legit but misses an ':' between 'alawar' and 'motor_town'

        assert_eq!(is_valid_cpe_string("cpe:2.3:a:alawar:motor_town\\:_machine_soul_free:1.1:*:*:*:*:android:*:*"), true);
        assert_eq!(is_valid_cpe_string("cpe:2.3:o:linux:linux_kernel:5.4.21:*:*:*:*:*:*:*"), true);
        assert_eq!(is_valid_cpe_string("cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*"), true);
    }
}