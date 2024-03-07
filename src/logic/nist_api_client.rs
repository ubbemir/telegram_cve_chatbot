const BASE_URL: &str = "https://services.nvd.nist.gov/rest/json/cves/2.0";

use std::{error::Error, fmt, sync::Arc};
use super::nist_api_structs::*;
use regex::Regex;
use chrono::prelude::*;

#[derive(Debug)]
struct NISTApiError(String);
unsafe impl Send for NISTApiError {}
impl fmt::Display for NISTApiError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "NIST_API_ERROR: {}", self.0)
    }
}
impl Error for NISTApiError {}


pub fn is_valid_cpe_string(cpe: &str) -> bool {
    let re = Regex::new(r###"cpe:2\.3:[aho\*\-](:(((\?*|\*?)([a-zA-Z0-9\-\._]|(\\[\\\*\?!"#$$%&'\(\)\+,/:;<=>@\[\]\^`\{\|}~]))+(\?*|\*?))|[\*\-])){5}(:(([a-zA-Z]{2,3}(-([a-zA-Z]{2}|[0-9]{3}))?)|[\*\-]))(:(((\?*|\*?)([a-zA-Z0-9\-\._]|(\\[\\\*\?!"#$$%&'\(\)\+,/:;<=>@\[\]\^`\{\|}~]))+(\?*|\*?))|[\*\-])){4}"###).unwrap();
    return re.is_match(cpe);
}

pub fn is_valid_cve_string(cve: &str) -> bool {
    let re = Regex::new(r#"CVE-\d{4}-\d{4,7}$"#).unwrap();
    return re.is_match(cve);
}

fn format_timestamp(timestamp_seconds: i64) -> String {
    let datetime: DateTime<Utc> = DateTime::from_timestamp(timestamp_seconds, 0).unwrap();

    let mut newdate = datetime.format("%Y-%m-%dT%H:%M:%S.000").to_string();
    newdate.push_str("%2B01:00");
    newdate
}

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
            eprintln!("Failed to fetch {} - Status code: {}", url, response.status());
            return Err(Box::new(NISTApiError(format!("API endpoint refused: Code {}", response.status()))));
        }
        
        let response: CPEResponse = match response.json::<CPEResponse>().await {
            Ok(res) => res,
            Err(_) => return Err(Box::new(NISTApiError("Failed to parse response as json".into())))
        };

        Ok(response)
    }

    pub async fn get_cves_from_cpe(&self, cpe: &str, amount: Option<u64>, page: Option<u64>) -> Result<CPEResponse, Box<dyn Error + Send>> {
        if let None = amount {
            let params = format!("cpeName={}", urlencoding::encode(&cpe));
            let response = self.query_nist(params).await?;

            return Ok(response);
        }
        let amount = amount.unwrap();
        let page = page.unwrap_or(1);
        
        // this first request is used to get the total amount of CVEs
        let params = format!("cpeName={}&resultsPerPage=1", urlencoding::encode(&cpe));
        let response = self.query_nist(params).await?;

        let mut start_index = 0;
        if (amount * page) < response.totalResults {
            start_index = response.totalResults - amount * page; 
        }
        
        let params = format!("cpeName={}&resultsPerPage={}&startIndex={}", urlencoding::encode(&cpe), amount, start_index);
        let response = self.query_nist(params).await?;

        Ok(response)
    }

    pub async fn get_latest_updated_cves_from_cpe(&self, cpe: &str, start_date: i64, end_date: i64) -> Result<CPEResponse, Box<dyn Error + Send>> {
        let start_date = format_timestamp(start_date);
        let end_date = format_timestamp(end_date);
        
        let params = format!("cpeName={}&lastModStartDate={}&lastModEndDate={}", urlencoding::encode(cpe), start_date, end_date);
        let response = self.query_nist(params).await?;

        Ok(response)
    }

    pub async fn get_cve_info(&self, cve: &str) -> Result<CPEResponse, Box<dyn Error + Send>> {
        let params = format!("cveId={}", urlencoding::encode(cve));
        let response = self.query_nist(params).await?;

        Ok(response)
    }
}


#[cfg(test)]
mod unit_tests {
    use crate::logic::nist_api_client::is_valid_cve_string;

    use super::is_valid_cpe_string;
    use super::format_timestamp;

    #[test]
    fn is_valid_cpe_string_test() {
        assert_eq!(is_valid_cpe_string("test123"), false);
        assert_eq!(is_valid_cpe_string("cpe:2.3:a:alawarmotor_town\\:_machine_soul_free:1.1:*:*:*:*:android:*:*"), false); // looks legit but misses an ':' between 'alawar' and 'motor_town'

        assert_eq!(is_valid_cpe_string("cpe:2.3:a:alawar:motor_town\\:_machine_soul_free:1.1:*:*:*:*:android:*:*"), true);
        assert_eq!(is_valid_cpe_string("cpe:2.3:o:linux:linux_kernel:5.4.21:*:*:*:*:*:*:*"), true);
        assert_eq!(is_valid_cpe_string("cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*"), true);
    }

    #[test]
    fn is_valid_cve_string_test() {
        assert_eq!(is_valid_cve_string("jddjkhYDDKDK"), false);
        assert_eq!(is_valid_cve_string("CVE-2015-4000-"), false);

        assert_eq!(is_valid_cve_string("CVE-2015-4000"), true);
        assert_eq!(is_valid_cve_string("CVE-2009-1394"), true);
        assert_eq!(is_valid_cve_string("CVE-1999-0524"), true);
    }

    #[test]
    fn format_timestamp_test() {
        assert_eq!(format_timestamp(1628082000), "2021-08-04T13:00:00.000%2B01:00");
        assert_eq!(format_timestamp(1634909760), "2021-10-22T13:36:00.000%2B01:00");
    }
}