mod client;
mod config;
mod error;
mod graphql;
mod output;

pub mod cli;

pub use cli::{Cli, run};
pub use error::{Error, Result};
pub use output::OutputFormat;
