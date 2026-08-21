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
        allow_custom_endpoints: bool,
    ) -> Result<Self> {
        Ok(Self {
            endpoint: validated_url(
                "WIZ_API_ENDPOINT",
                &endpoint,
                allow_insecure_http,
                allow_custom_endpoints,
            )?,
            auth_endpoint: validated_url(
                "WIZ_AUTH_ENDPOINT",
                &auth_endpoint,
                allow_insecure_http,
                allow_custom_endpoints,
            )?,
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

fn validated_url(
    name: &str,
    value: &str,
    allow_insecure_http: bool,
    allow_custom_endpoints: bool,
) -> Result<Url> {
    let url =
        Url::parse(value).map_err(|e| Error::Config(format!("{name} is not a valid URL: {e}")))?;
    if !url.username().is_empty() || url.password().is_some() {
        return Err(Error::Config(format!(
            "{name} must not include URL credentials"
        )));
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err(Error::Config(format!(
            "{name} must not include a query string or fragment"
        )));
    }
    let host = url
        .host_str()
        .ok_or_else(|| Error::Config(format!("{name} must include a host")))?;
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
    let is_loopback = match url.host() {
        Some(url::Host::Ipv4(address)) => address.is_loopback(),
        Some(url::Host::Ipv6(address)) => address.is_loopback(),
        Some(url::Host::Domain("localhost")) => true,
        _ => false,
    };
    let is_wiz = host == "wiz.io" || host.ends_with(".wiz.io");
    if !is_wiz && !(allow_insecure_http && is_loopback) && !allow_custom_endpoints {
        return Err(Error::Config(format!(
            "{name} must use a wiz.io host; pass --allow-custom-endpoints only if you trust the configured host to receive credentials"
        )));
    }
    Ok(url)
}

#[cfg(test)]
mod tests {
    use super::validated_url;

    #[test]
    fn accepts_wiz_https_and_explicit_loopback_http() {
        assert!(
            validated_url(
                "endpoint",
                "https://api.us1.app.wiz.io/graphql",
                false,
                false
            )
            .is_ok()
        );
        assert!(validated_url("endpoint", "http://127.0.0.1/graphql", true, false).is_ok());
        assert!(validated_url("endpoint", "https://tenant.auth0.com/token", false, true).is_ok());
    }

    #[test]
    fn rejects_credential_exfiltration_origins_and_unsafe_url_parts() {
        for value in [
            "https://example.com/graphql",
            "https://wiz.io.evil.example/graphql",
            "https://api.app.wiz.io./graphql",
            "https://user:pass@api.app.wiz.io/graphql",
            "https://api.app.wiz.io/graphql?token=secret",
            "https://api.app.wiz.io/graphql#secret",
            "https://[::1]/graphql",
        ] {
            assert!(
                validated_url("endpoint", value, false, false).is_err(),
                "unexpectedly accepted {value}"
            );
        }
    }
}
