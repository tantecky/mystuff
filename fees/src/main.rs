mod exchange;
mod fiat;
mod util;
use exchange::Exchange;
use fiat::Fiat;
use regex::Regex;
use std::process::Command;
use tokio::join;

#[tokio::main]
async fn main() {
    let kraken = Exchange {
        url: "https://support.kraken.com/hc/en-us/articles/360000767986-Cryptocurrency-withdrawal-fees-and-minimums".to_owned(),
        fee_regex: Regex::new(r"(0.\d+).BTC").unwrap()
    };

    let fiat = Fiat {
        data_source: "https://www.bitstamp.net/api/v2/ticker/btcusd".to_owned(),
    };

    let fee_future = kraken.withdrawal_fee();
    let fiat_future = fiat.btc_2_usd();

    let (fee_result, fiat_result) = join!(fee_future, fiat_future);

    match fee_result {
        Ok(fee) => match fiat_result {
            Ok(btc_2_usd) => println!(
                "Kraken withdrawal fee {} BTC = {} USD",
                fee,
                fee * btc_2_usd
            ),
            Err(err) => panic!("{:?}", err),
        },

        Err(err) => panic!("{:?}", err),
    }

    let _ = Command::new("cmd.exe").arg("/c").arg("pause").status();
}
