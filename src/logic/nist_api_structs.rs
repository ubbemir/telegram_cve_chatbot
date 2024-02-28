use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize)]
#[allow(non_snake_case)]
pub struct CPEResponse {
    pub vulnerabilities: Vec<CVEContainer>,
    pub totalResults: u64
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
    pub metrics: CVSSMetricContainer

}

#[derive(Serialize, Deserialize)]
#[allow(non_snake_case)]
pub struct CVEDetail {
    pub lang: String,
    pub value: String
}

#[derive(Serialize, Deserialize)]
#[allow(non_snake_case)]
pub struct CVSSMetricContainer {
    pub cvssMetricV2: Option<Vec<CVSSMetricV2>>,
    pub cvssMetricV31: Option<Vec<CVSSMetricV31>>
}

#[derive(Serialize, Deserialize)]
#[allow(non_snake_case)]
pub struct CVSSMetricV2 {
    pub source: String,
    pub baseSeverity: String,

    #[serde(rename = "type")] 
    pub t: String
}

#[derive(Serialize, Deserialize)]
#[allow(non_snake_case)]
pub struct CVSSMetricV31 {
    pub source: String,
    pub cvssData: CVSSV31Data,

    #[serde(rename = "type")] 
    pub t: String
}

#[derive(Serialize, Deserialize)]
#[allow(non_snake_case)]
pub struct CVSSV31Data {
    version: String,
    baseSeverity: String
}

impl CVE {
    pub fn get_base_severity(&self) -> Option<&String> {
        if let Some(metrics) = &self.metrics.cvssMetricV31 {
            return Some(&metrics[0].cvssData.baseSeverity);
        }
        
        if let Some(metrics) = &self.metrics.cvssMetricV2 {
            return Some(&metrics[0].baseSeverity);
        }

        None
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