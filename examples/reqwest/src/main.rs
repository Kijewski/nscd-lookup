use clap::Parser;
use nscd_lookup::reqwest::resolver;
use reqwest::{Client, Url};
use tokio::main;

#[main(flavor = "current_thread")]
async fn main() -> Result<(), Error> {
    let args = Args::parse();
    let text = Client::builder()
        .dns_resolver(resolver())
        .user_agent(
            "Mozilla/5.0 (X11; Linux x86_64; rv:135.0) Gecko/20100101 Firefox/135.0 \
            +https://github.com/Kijewski/nscd-lookup",
        )
        .build()
        .map_err(Error::Builder)?
        .get(args.url)
        .send()
        .await
        .map_err(Error::Get)?
        .error_for_status()
        .map_err(Error::Status)?
        .text()
        .await
        .map_err(Error::Text)?;
    println!("{text}");
    Ok(())
}

#[derive(pretty_error_debug::Debug, thiserror::Error, displaydoc::Display)]
enum Error {
    /// Could not build reqwest client
    Builder(#[source] reqwest::Error),
    /// Could not query URL
    Get(#[source] reqwest::Error),
    /// URL returned an HTTP error
    Status(#[source] reqwest::Error),
    /// Could not interpret response text
    Text(#[source] reqwest::Error),
}

/// Get the context of some website
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// url to get
    url: Url,
}
