use rust_decimal::prelude::*;
use rust_decimal::Decimal;

pub struct Exchange {
    pub url: String,
}

impl Exchange {
    pub fn withdrawal_fee(self) -> Decimal {
        Decimal::from_str("2.02").unwrap()
    }
}

fn fetch_data(exchange: Exchange) {
    let resp = reqwest::blocking::get(exchange.url);
}
