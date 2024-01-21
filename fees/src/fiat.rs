use crate::util::fetch;
use reqwest::Error;
use rust_decimal::Decimal;
use serde_json::Value;
use std::str::FromStr;

pub struct Fiat {
    pub data_source: String,
}

impl Fiat {
    pub async fn btc_2_usd(&self) -> Result<Decimal, Error> {
        let data = fetch(&self.data_source).await?;

        let json: Value = serde_json::from_str(&data).unwrap();
        let last = &json["last"];

        Ok(Decimal::from_str(last.as_str().unwrap()).unwrap())
    }
}
