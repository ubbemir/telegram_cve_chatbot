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