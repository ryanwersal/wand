use std::time::Duration;

use reqwest::{Client, StatusCode, redirect::Policy};
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use serde_json::Value;
use tokio::time::sleep;

use crate::{Error, Result, config::Config, graphql};

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    #[allow(dead_code)]
    expires_in: Option<u64>,
}

pub struct WizClient {
    http: Client,
    config: Config,
    token: SecretString,
}

impl WizClient {
    pub async fn authenticate(config: Config) -> Result<Self> {
        let http = Client::builder()
            .user_agent(concat!("wand/", env!("CARGO_PKG_VERSION")))
            .timeout(Duration::from_secs(config.timeout_seconds))
            .redirect(Policy::none())
            .build()
            .map_err(|e| Error::Config(format!("failed to build HTTP client: {e}")))?;
        let mut response = None;
        for attempt in 0..=config.retries {
            match http
                .post(config.auth_endpoint.clone())
                .form(&[
                    ("grant_type", "client_credentials"),
                    ("client_id", config.client_id.as_str()),
                    ("client_secret", config.client_secret.expose_secret()),
                    ("audience", config.audience.as_str()),
                ])
                .send()
                .await
            {
                Ok(candidate)
                    if (candidate.status() == StatusCode::TOO_MANY_REQUESTS
                        || candidate.status().is_server_error())
                        && attempt < config.retries =>
                {
                    sleep(retry_delay(&candidate, attempt)).await;
                }
                Ok(candidate) => {
                    response = Some(candidate);
                    break;
                }
                Err(error)
                    if attempt < config.retries && (error.is_connect() || error.is_timeout()) =>
                {
                    sleep(backoff(attempt)).await;
                }
                Err(error) => return Err(safe_transport_error(&error)),
            }
        }
        let response =
            response.ok_or_else(|| Error::Transport("authentication retries exhausted".into()))?;
        if !response.status().is_success() {
            return Err(Error::Authentication(format!(
                "HTTP {}",
                response.status().as_u16()
            )));
        }
        let token = read_json::<TokenResponse>(response, config.max_response_bytes)
            .await
            .map_err(|e| Error::Authentication(format!("invalid token response: {e}")))?;
        if token.access_token.is_empty() {
            return Err(Error::Authentication(
                "token response contained an empty access token".into(),
            ));
        }
        Ok(Self {
            http,
            config,
            token: SecretString::from(token.access_token),
        })
    }

    pub async fn query(
        &self,
        query: &str,
        variables: Value,
        operation_name: Option<&str>,
    ) -> Result<graphql::Response> {
        for attempt in 0..=self.config.retries {
            let result = self
                .http
                .post(self.config.endpoint.clone())
                .bearer_auth(self.token.expose_secret())
                .json(&graphql::Request {
                    query,
                    variables: variables.clone(),
                    operation_name,
                })
                .send()
                .await;
            let response = match result {
                Ok(response) => response,
                Err(error)
                    if attempt < self.config.retries
                        && (error.is_connect() || error.is_timeout()) =>
                {
                    sleep(backoff(attempt)).await;
                    continue;
                }
                Err(error) => return Err(safe_transport_error(&error)),
            };
            let status = response.status();
            if (status == StatusCode::TOO_MANY_REQUESTS || status.is_server_error())
                && attempt < self.config.retries
            {
                sleep(retry_delay(&response, attempt)).await;
                continue;
            }
            if status == StatusCode::UNAUTHORIZED {
                return Err(Error::Authentication(
                    "GraphQL request returned HTTP 401".into(),
                ));
            }
            if status == StatusCode::FORBIDDEN {
                return Err(Error::Authorization(
                    "GraphQL request returned HTTP 403".into(),
                ));
            }
            if status == StatusCode::TOO_MANY_REQUESTS {
                return Err(Error::RateLimit(format!(" (HTTP {})", status.as_u16())));
            }
            if !status.is_success() {
                return Err(Error::Transport(format!(
                    "GraphQL request returned HTTP {}",
                    status.as_u16()
                )));
            }
            let mut response: graphql::Response =
                read_json(response, self.config.max_response_bytes).await?;
            for error in &mut response.errors {
                redact_known_value(&mut error.message, self.token.expose_secret());
                redact_known_value(&mut error.message, &self.config.client_id);
                redact_known_value(
                    &mut error.message,
                    self.config.client_secret.expose_secret(),
                );
            }
            return Ok(response);
        }
        unreachable!("retry loop always returns")
    }
}

async fn read_json<T: serde::de::DeserializeOwned>(
    mut response: reqwest::Response,
    limit: usize,
) -> Result<T> {
    if response
        .content_length()
        .is_some_and(|length| length > limit as u64)
    {
        return Err(Error::Response(format!(
            "response exceeds {limit} byte limit"
        )));
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|error| safe_transport_error(&error))?
    {
        if body.len().saturating_add(chunk.len()) > limit {
            return Err(Error::Response(format!(
                "response exceeds {limit} byte limit"
            )));
        }
        body.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&body).map_err(|e| Error::Response(e.to_string()))
}

fn safe_transport_error(error: &reqwest::Error) -> Error {
    let message = if error.is_timeout() {
        "request timed out"
    } else if error.is_connect() {
        "connection failed"
    } else if error.is_request() {
        "request failed"
    } else if error.is_body() || error.is_decode() {
        "response transfer failed"
    } else {
        "network operation failed"
    };
    Error::Transport(message.into())
}

fn redact_known_value(message: &mut String, value: &str) {
    if value.chars().count() >= 8 && message.contains(value) {
        *message = message.replace(value, "[REDACTED]");
    }
}

fn backoff(attempt: u8) -> Duration {
    Duration::from_millis(100_u64.saturating_mul(1_u64 << attempt.min(8)))
}

fn retry_delay(response: &reqwest::Response, attempt: u8) -> Duration {
    response
        .headers()
        .get(reqwest::header::RETRY_AFTER)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .map(|seconds| Duration::from_secs(seconds.min(30)))
        .unwrap_or_else(|| backoff(attempt))
}
