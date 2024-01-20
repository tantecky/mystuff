use reqwest::Error;

pub async fn fetch(url: &String) -> Result<String, Error> {
    let data = reqwest::get(url).await?.text().await?;
    Ok(data)
}
