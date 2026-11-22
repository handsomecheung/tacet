use crate::error::UriError;
use percent_encoding::percent_decode_str;
use std::fmt;
use std::str::FromStr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Scope {
    /// `personal`: Personal vault (organizationId == null)
    Personal { folder: Option<String> },
    /// `org/<org_name>/<collection>`: Shared items inside an Organization's collection
    Organization {
        org_name: String,
        collection: String,
    },
    /// `*`: Search all accessible vaults (fails if ambiguous)
    All,
}

impl fmt::Display for Scope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Scope::Personal { folder: None } => write!(f, "personal"),
            Scope::Personal {
                folder: Some(folder),
            } => write!(f, "personal/{folder}"),
            Scope::Organization {
                org_name,
                collection,
            } => write!(f, "org/{org_name}/{collection}"),
            Scope::All => write!(f, "*"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CipherFieldTarget {
    Username,
    Password,
    Totp,
    TotpSecret,
    Uri(usize),
    Notes,
    CustomField(String),
    File(String),
    Named(String),
}

impl FromStr for CipherFieldTarget {
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let trimmed = s.trim();
        if let Some(field_name) = trimmed.strip_prefix("fields/") {
            return Ok(CipherFieldTarget::CustomField(field_name.to_string()));
        }
        if let Some(file_name) = trimmed.strip_prefix("files/") {
            return Ok(CipherFieldTarget::File(file_name.to_string()));
        }

        let lower = trimmed.to_lowercase();
        match lower.as_str() {
            "username" => Ok(CipherFieldTarget::Username),
            "password" => Ok(CipherFieldTarget::Password),
            "totp" => Ok(CipherFieldTarget::Totp),
            "totp_secret" => Ok(CipherFieldTarget::TotpSecret),
            "notes" => Ok(CipherFieldTarget::Notes),
            "uri" | "uri.0" => Ok(CipherFieldTarget::Uri(0)),
            other => {
                if let Some(idx_str) = other.strip_prefix("uri.") {
                    if let Ok(idx) = idx_str.parse::<usize>() {
                        return Ok(CipherFieldTarget::Uri(idx));
                    }
                }
                Ok(CipherFieldTarget::Named(trimmed.to_string()))
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encoding {
    Base64,
    Hex,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Modifiers {
    pub encoding: Option<Encoding>,
    pub json: Option<String>,
    pub trim: bool,
    pub trim_explicit: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TacetUri {
    pub raw: String,
    pub scope: Scope,
    pub item: String,
    pub field: CipherFieldTarget,
    /// Original decoded target name, preserving case for attachment fallback.
    pub target_name: String,
    pub modifiers: Modifiers,
}

impl FromStr for TacetUri {
    type Err = UriError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl TacetUri {
    pub fn parse(input: &str) -> Result<Self, UriError> {
        let trimmed = input.trim();
        let rest = trimmed
            .strip_prefix("tacet://")
            .ok_or(UriError::InvalidScheme)?;

        let (path_str, query_opt) = match rest.split_once('?') {
            Some((p, q)) => (p, Some(q)),
            None => (rest, None),
        };

        // Parse modifiers
        let mut modifiers = Modifiers::default();
        if let Some(query) = query_opt {
            for param in query.split('&') {
                if param.is_empty() {
                    continue;
                }
                let (k, v) = param
                    .split_once('=')
                    .ok_or_else(|| UriError::InvalidModifier(param.to_string()))?;

                match k.to_lowercase().as_str() {
                    "encoding" => match v.to_lowercase().as_str() {
                        "base64" => modifiers.encoding = Some(Encoding::Base64),
                        "hex" => modifiers.encoding = Some(Encoding::Hex),
                        other => {
                            return Err(UriError::InvalidModifier(format!(
                                "Unknown encoding: {other}"
                            )))
                        }
                    },
                    "json" => {
                        modifiers.json = Some(v.to_string());
                    }
                    "trim" => {
                        modifiers.trim_explicit = true;
                        match v.to_lowercase().as_str() {
                            "true" | "1" => modifiers.trim = true,
                            "false" | "0" => modifiers.trim = false,
                            other => {
                                return Err(UriError::InvalidModifier(format!(
                                    "Invalid trim value: {other}"
                                )))
                            }
                        }
                    }
                    other => {
                        return Err(UriError::InvalidModifier(format!(
                            "Unknown modifier: {other}"
                        )))
                    }
                }
            }
        }

        // Determine path structure before decoding names containing escaped slashes.
        let raw_segments: Vec<&str> = path_str
            .trim_start_matches('/')
            .split('/')
            .filter(|s| !s.is_empty())
            .collect();
        let segments: Vec<String> = raw_segments
            .iter()
            .map(|s| percent_decode_str(s).decode_utf8_lossy().to_string())
            .collect();
        let scope_name = segments
            .first()
            .ok_or(UriError::MissingComponent("Empty URI path"))?;
        let scope_start = match scope_name.as_str() {
            "personal" | "*" => 1,
            "org" => 2,
            other => return Err(UriError::InvalidScope(other.to_string())),
        };
        if segments.len() < scope_start + 2 {
            return Err(UriError::MissingComponent("URI requires item and target"));
        }
        let marker = raw_segments[raw_segments.len() - 2];
        let explicit = matches!(marker, "fields" | "files") && segments.len() >= scope_start + 3;
        let item_idx = segments.len() - if explicit { 3 } else { 2 };
        let name = segments[segments.len() - 1].clone();
        let target_name = name.clone();
        let field = if explicit {
            match marker {
                "fields" => CipherFieldTarget::CustomField(name),
                _ => CipherFieldTarget::File(name),
            }
        } else if name.contains('/') {
            CipherFieldTarget::Named(name)
        } else {
            name.parse().map_err(|_: std::convert::Infallible| {
                UriError::MissingComponent("Invalid target")
            })?
        };
        let scope = match scope_name.as_str() {
            "personal" => Scope::Personal {
                folder: (item_idx > 1).then(|| segments[1..item_idx].join("/")),
            },
            "org" => {
                if item_idx <= 2 {
                    return Err(UriError::MissingComponent(
                        "Organization URI requires a collection",
                    ));
                }
                Scope::Organization {
                    org_name: segments[1].clone(),
                    collection: segments[2..item_idx].join("/"),
                }
            }
            _ => {
                if item_idx != 1 {
                    return Err(UriError::MissingComponent(
                        "Wildcard URI requires item and target, without a folder",
                    ));
                }
                Scope::All
            }
        };
        Ok(Self {
            raw: trimmed.to_string(),
            scope,
            item: segments[item_idx].clone(),
            field,
            target_name,
            modifiers,
        })
    }
}
