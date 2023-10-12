use zap::error::ZapError;
use crate::cli_util::Args;
use clap::Parser;

mod cli_util;

fn main() -> Result<(), anyhow::Error> {
    Args::parse().execute()
}
