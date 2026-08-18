use secrecy::SecretString;
use url::Url;

use crate::{Error, Result};

#[derive(Clone)]
pub struct Config {
    pub endpoint: Url,
    pub auth_endpoint: Url,
    pub audience: String,
    pub client_id: String,
    pub client_secret: SecretString,
    pub timeout_seconds: u64,
    pub retries: u8,
    pub max_response_bytes: usize,
}

impl Config {
    pub fn new(
        endpoint: String,
        auth_endpoint: String,
        audience: String,
        client_id: String,
        client_secret: String,
        allow_insecure_http: bool,
    ) -> Result<Self> {
        Ok(Self {
            endpoint: validated_url("WIZ_API_ENDPOINT", &endpoint, allow_insecure_http)?,
            auth_endpoint: validated_url("WIZ_AUTH_ENDPOINT", &auth_endpoint, allow_insecure_http)?,
            audience,
            client_id,
            client_secret: SecretString::from(client_secret),
            timeout_seconds: 30,
            retries: 2,
            max_response_bytes: 10_485_760,
        })
    }

    pub fn with_transport(
        mut self,
        timeout_seconds: u64,
        retries: u8,
        max_response_bytes: usize,
    ) -> Self {
        self.timeout_seconds = timeout_seconds;
        self.retries = retries;
        self.max_response_bytes = max_response_bytes;
        self
    }
}

fn validated_url(name: &str, value: &str, allow_insecure_http: bool) -> Result<Url> {
    let url =
        Url::parse(value).map_err(|e| Error::Config(format!("{name} is not a valid URL: {e}")))?;
    if url.scheme() != "https" {
        let loopback = match url.host() {
            Some(url::Host::Ipv4(address)) => address.is_loopback(),
            Some(url::Host::Ipv6(address)) => address.is_loopback(),
            Some(url::Host::Domain("localhost")) => true,
            _ => false,
        };
        if url.scheme() != "http" || !allow_insecure_http || !loopback {
            return Err(Error::Config(format!(
                "{name} must use HTTPS; insecure HTTP is test-only and restricted to loopback hosts"
            )));
        }
    }
    if url.host_str().is_none() {
        return Err(Error::Config(format!("{name} must include a host")));
    }
    Ok(url)
}
