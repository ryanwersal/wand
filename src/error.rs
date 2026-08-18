use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("configuration error: {0}")]
    Config(String),
    #[error("invalid input: {0}")]
    Input(String),
    #[error("authentication failed: {0}")]
    Authentication(String),
    #[error("Wiz denied access: {0}")]
    Authorization(String),
    #[error("Wiz rate limit exceeded{0}")]
    RateLimit(String),
    #[error("network request failed: {0}")]
    Transport(String),
    #[error("Wiz GraphQL error: {message}")]
    Graphql {
        message: String,
        details: serde_json::Value,
    },
    #[error("invalid response from Wiz: {0}")]
    Response(String),
    #[error("not found: {0}")]
    NotFound(String),
    #[error("I/O error: {0}")]
    Io(String),
}

impl Error {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Config(_) => "configuration_error",
            Self::Input(_) => "invalid_input",
            Self::Authentication(_) => "authentication_failed",
            Self::Authorization(_) => "forbidden",
            Self::RateLimit(_) => "rate_limited",
            Self::Transport(_) => "transport_error",
            Self::Graphql { .. } => "graphql_error",
            Self::Response(_) => "invalid_response",
            Self::NotFound(_) => "not_found",
            Self::Io(_) => "io_error",
        }
    }

    pub fn exit_code(&self) -> i32 {
        match self {
            Self::Config(_) | Self::Input(_) => 2,
            Self::Authentication(_) | Self::Authorization(_) => 3,
            Self::NotFound(_) => 4,
            Self::RateLimit(_) | Self::Transport(_) => 5,
            Self::Graphql { .. } | Self::Response(_) | Self::Io(_) => 1,
        }
    }

    pub fn details(&self) -> Option<&serde_json::Value> {
        match self {
            Self::Graphql { details, .. } => Some(details),
            _ => None,
        }
    }
}
