//! Configuration: what the honeypot claims to be, and which credentials it
//! pretends to accept.

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use std::net::SocketAddr;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub server: ServerCfg,
    #[serde(default)]
    pub identity: Identity,
    #[serde(default)]
    pub log: LogCfg,
    #[serde(default)]
    pub credentials: Vec<Credential>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerCfg {
    #[serde(default = "default_listen")]
    pub listen: String,
    /// Which WWW-Authenticate schemes to advertise, in order.
    #[serde(default = "default_schemes")]
    pub schemes: Vec<Scheme>,
}

fn default_listen() -> String {
    "0.0.0.0:5985".to_string()
}

fn default_schemes() -> Vec<Scheme> {
    vec![Scheme::Negotiate, Scheme::Basic]
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Scheme {
    Negotiate,
    Basic,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Identity {
    #[serde(default = "default_computer_name")]
    pub computer_name: String,
    #[serde(default = "default_domain")]
    pub domain: String,
    #[serde(default = "default_dns_domain")]
    pub dns_domain: String,
    /// "major.minor.build", e.g. "10.0.20348" (Server 2022).
    #[serde(default = "default_os_version")]
    pub os_version: String,
}

fn default_computer_name() -> String {
    "WIN-SRV01".to_string()
}

fn default_domain() -> String {
    "CORP".to_string()
}

fn default_dns_domain() -> String {
    "corp.local".to_string()
}

fn default_os_version() -> String {
    "10.0.20348".to_string()
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogCfg {
    /// Path to the event log, or "-" for stdout (containers).
    #[serde(default = "default_log_path")]
    pub path: String,
}

fn default_log_path() -> String {
    "logs/winrm-events.log".to_string()
}

// `#[serde(default)]` on a struct-typed field requires the type itself to be
// Default; these impls must stay in sync with the per-field serde defaults.
impl Default for ServerCfg {
    fn default() -> Self {
        Self {
            listen: default_listen(),
            schemes: default_schemes(),
        }
    }
}

impl Default for Identity {
    fn default() -> Self {
        Self {
            computer_name: default_computer_name(),
            domain: default_domain(),
            dns_domain: default_dns_domain(),
            os_version: default_os_version(),
        }
    }
}

impl Default for LogCfg {
    fn default() -> Self {
        Self {
            path: default_log_path(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Credential {
    pub username: String,
    pub password: String,
    /// Defaults to identity.domain when omitted.
    #[serde(default)]
    pub domain: Option<String>,
}

impl Credential {
    pub fn domain_or<'a>(&'a self, default: &'a str) -> &'a str {
        self.domain.as_deref().unwrap_or(default)
    }
}

impl Config {
    pub fn from_toml_str(s: &str) -> Result<Self> {
        let cfg: Config = toml::from_str(s).context("parsing config TOML")?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn load(path: &std::path::Path) -> Result<Self> {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        Config::from_toml_str(&text)
    }

    fn validate(&self) -> Result<()> {
        let _: SocketAddr =
            self.server.listen.parse().with_context(|| {
                format!("server.listen {:?} is not an IP:port", self.server.listen)
            })?;
        if self.server.schemes.is_empty() {
            bail!("server.schemes must list at least one of: negotiate, basic");
        }
        if self.credentials.is_empty() {
            bail!("at least one [[credentials]] entry is required");
        }
        for (i, c) in self.credentials.iter().enumerate() {
            if c.username.trim().is_empty() {
                bail!("credentials[{i}].username must not be empty");
            }
            if c.password.is_empty() {
                bail!("credentials[{i}].password must not be empty");
            }
        }
        parse_os_version(&self.identity.os_version)?;
        Ok(())
    }

    pub fn has_scheme(&self, s: Scheme) -> bool {
        self.server.schemes.contains(&s)
    }

    /// Case-insensitive (domain, username) lookup. The machine's own NetBIOS
    /// name is accepted as the domain for local accounts.
    pub fn find_credential(&self, domain: &str, user: &str) -> Option<&Credential> {
        let d = domain.trim().to_lowercase();
        let u = user.trim().to_lowercase();
        let own = self.identity.computer_name.to_lowercase();
        self.credentials.iter().find(|c| {
            let cd = c.domain_or(&self.identity.domain).to_lowercase();
            c.username.to_lowercase() == u && (cd == d || own == d)
        })
    }
}

/// "10.0.20348" -> (10, 0, 20348)
pub fn parse_os_version(s: &str) -> Result<(u8, u8, u16)> {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 3 {
        bail!("identity.os_version must look like \"10.0.20348\", got {s:?}");
    }
    Ok((
        parts[0].parse().context("os_version major")?,
        parts[1].parse().context("os_version minor")?,
        parts[2].parse().context("os_version build")?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_one_credential() {
        let cfg = Config::from_toml_str(
            r#"
            [[credentials]]
            username = "Administrator"
            password = "Summer2026!"
            "#,
        )
        .unwrap();

        assert_eq!(cfg.credentials.len(), 1);
        assert_eq!(cfg.credentials[0].username, "Administrator");
        assert_eq!(cfg.identity.domain, "CORP");
        assert_eq!(cfg.server.listen, "0.0.0.0:5985");
    }

    #[test]
    fn finds_credential_case_insensitively() {
        let cfg = Config::from_toml_str(
            r#"
            [[credentials]]
            domain = "Corp"
            username = "Administrator"
            password = "p"
            [[credentials]]
            username = "svc_backup"
            password = "q"
            "#,
        )
        .unwrap();

        assert!(cfg.find_credential("CORP", "administrator").is_some());
        assert!(cfg.find_credential("corp", "ADMINISTRATOR").is_some());
        // second credential inherits identity.domain ("CORP")
        assert!(cfg.find_credential("CORP", "svc_backup").is_some());
        assert!(cfg.find_credential("OTHER", "svc_backup").is_none());
        assert!(cfg.find_credential("CORP", "nobody").is_none());
    }

    #[test]
    fn accepts_computer_name_as_local_domain() {
        let cfg = Config::from_toml_str(
            r#"
            [[credentials]]
            username = "Administrator"
            password = "p"
            "#,
        )
        .unwrap();
        assert!(cfg.find_credential("WIN-SRV01", "Administrator").is_some());
    }

    #[test]
    fn rejects_empty_credentials() {
        let err = Config::from_toml_str("[server]\nlisten = \"127.0.0.1:0\"\n")
            .unwrap_err()
            .to_string();
        assert!(err.contains("at least one [[credentials]]"), "{err}");
    }

    #[test]
    fn rejects_unknown_field() {
        let err = Config::from_toml_str(
            r#"
            [server]
            lstien = "127.0.0.1:0"
            [[credentials]]
            username = "a"
            password = "b"
            "#,
        )
        .unwrap_err();
        // `{:#}` prints the whole context chain, which is what main() shows.
        let msg = format!("{err:#}").to_lowercase();
        assert!(msg.contains("lstien"), "{msg}");
    }

    #[test]
    fn rejects_malformed_os_version() {
        let err = Config::from_toml_str(
            r#"
            [identity]
            os_version = "Server 2022"
            [[credentials]]
            username = "a"
            password = "b"
            "#,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("os_version"), "{err}");
    }

    /// The shipped example must stay loadable, otherwise the docs rot silently.
    #[test]
    fn example_config_loads() {
        let cfg = Config::load("config.example.toml".as_ref()).expect("example config must load");
        assert_eq!(cfg.credentials.len(), 2);
        assert_eq!(cfg.identity.computer_name, "WIN-SRV01");
    }
}
