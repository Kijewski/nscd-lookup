use std::process::exit;

use clap::Parser;
use nscd_lookup::sync::{Error, lookup};

fn main() -> Result<(), pretty_error_debug::Wrapper<Error>> {
    let args = Args::parse();
    if let Some(iter) = lookup(args.host, &mut Vec::new(), None)? {
        for addr in iter {
            println!("{addr}");
        }
        Ok(())
    } else {
        eprintln!("No addresses.");
        exit(1);
    }
}

/// Synchronous nscd host name look up example
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// host name to look up
    host: String,
}
