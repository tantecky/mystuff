use crate::util::fetch;
use reqwest::Error;

pub struct Fiat {
    pub data_source: String,
}

impl Fiat {
    pub async fn btc_2_usd(&self) -> Result<f64, Error> {
        let data = fetch(&self.data_source).await?;
        Ok(1.0)
    }
}
