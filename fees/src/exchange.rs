use crate::util::fetch;
use regex::Regex;
use reqwest::Error;
use rust_decimal::prelude::*;
use rust_decimal::Decimal;

pub struct Exchange {
    pub url: String,
    pub fee_regex: Regex,
}

impl Exchange {
    pub async fn withdrawal_fee(&self) -> Result<Decimal, Error> {
        let data = fetch(&self.url).await?;
        extract_fee(self, &data)
    }
}

fn extract_fee(exchange: &Exchange, data: &str) -> Result<Decimal, Error> {
    let captures = exchange.fee_regex.captures(data).unwrap();
    Ok(Decimal::from_str(&captures[1]).unwrap())
}
