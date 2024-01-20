mod exchange;
mod fiat;
mod util;
use exchange::Exchange;
use fiat::Fiat;
use regex::Regex;
use rust_decimal::prelude::ToPrimitive;

#[tokio::main]
async fn main() {
    let kraken = Exchange {
        url: "https://support.kraken.com/hc/en-us/articles/360000767986-Cryptocurrency-withdrawal-fees-and-minimums".to_owned(),
        fee_regex: Regex::new(r"(0.\d+).BTC").unwrap()
    };

    let fiat = Fiat {
        data_source: "https://www.bitstamp.net/api/v2/ticker/btcusd".to_owned(),
    };

    let fee = kraken.withdrawal_fee();
    let one_btc_in_usd = fiat.btc_2_usd();

    match fee.await {
        Ok(fee) => match one_btc_in_usd.await {
            Ok(rate) => println!(
                "Kraken withdrawal fee {} BTC, {} USD",
                fee,
                fee.to_f64().unwrap() * rate
            ),
            Err(err) => panic!("{:?}", err),
        },

        Err(err) => panic!("{:?}", err),
    }
}
