mod exchange;
use exchange::Exchange;

fn main() {
    let kraken = Exchange {
        url: String::from("https://support.kraken.com/hc/en-us/articles/360000767986-Cryptocurrency-withdrawal-fees-and-minimums")
    };

    println!("Kraken withdrawal fee {} BTC", kraken.withdrawal_fee())
}
