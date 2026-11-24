use crate::error::UpstreamError;
use crate::upstream::models::{
    AttachmentDownloadResponse, PreloginRequest, PreloginResponse, SyncResponse, TokenResponse,
    TwoFactorCredentials, TwoFactorErrorResponse,
};
use crate::upstream::urls::BitwardenEndpoints;
use reqwest::{Client, StatusCode};
use std::collections::HashMap;

pub const MAX_ATTACHMENT_BYTES: usize = 64 * 1024 * 1024;

pub fn normalize_api_client_id(client_id: &str) -> String {
    let client_id = client_id.trim().trim_matches('"').trim_matches('\'');
    if client_id.starts_with("user.") || client_id.starts_with("organization.") {
        client_id.to_string()
    } else {
        format!("user.{client_id}")
    }
}

#[derive(Clone, Debug)]
pub struct UpstreamClient {
    endpoints: BitwardenEndpoints,
    client: Client,
}

fn current_device_type() -> &'static str {
    #[cfg(target_os = "linux")]
    {
        "25"
    }
    #[cfg(target_os = "macos")]
    {
        "24"
    }
    #[cfg(target_os = "windows")]
    {
        "23"
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        "25"
    }
}

impl UpstreamClient {
    pub fn new(server_url: &str) -> Result<Self, UpstreamError> {
        let endpoints = BitwardenEndpoints::resolve(server_url)?;
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()?;
        Ok(Self { endpoints, client })
    }

    pub fn from_endpoints(endpoints: BitwardenEndpoints) -> Self {
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .unwrap_or_default();
        Self { endpoints, client }
    }

    pub fn endpoints(&self) -> &BitwardenEndpoints {
        &self.endpoints
    }

    /// Obtains a fresh download URL; older servers can expose it only in sync metadata.
    pub async fn download_attachment(
        &self,
        access_token: &str,
        cipher_id: &str,
        attachment_id: &str,
        fallback_url: Option<&str>,
    ) -> Result<Vec<u8>, UpstreamError> {
        let mut url = self.endpoints.api_url.clone();
        url.path_segments_mut()
            .map_err(|_| UpstreamError::InvalidAttachmentUrl)?
            .pop_if_empty()
            .extend(["ciphers", cipher_id, "attachment", attachment_id]);
        let resp = self
            .client
            .get(url)
            .bearer_auth(access_token)
            .send()
            .await
            .map_err(|e| UpstreamError::RequestFailed(e.without_url()))?;
        let status = resp.status();
        let download_url = if status == StatusCode::NOT_FOUND && fallback_url.is_some() {
            fallback_url
                .map(str::to_owned)
                .ok_or(UpstreamError::InvalidAttachmentUrl)?
        } else if status.is_success() {
            resp.json::<AttachmentDownloadResponse>()
                .await
                .map_err(|e| UpstreamError::RequestFailed(e.without_url()))?
                .url
        } else if status == StatusCode::UNAUTHORIZED {
            return Err(UpstreamError::AuthenticationFailed(
                "Vault server rejected the access token".into(),
            ));
        } else {
            return Err(UpstreamError::HttpStatusError {
                status: status.as_u16(),
                message: "Could not obtain attachment download URL".into(),
            });
        };
        let download_url = self.endpoints.api_url.join(&download_url)?;
        if !matches!(download_url.scheme(), "https" | "http")
            || (self.endpoints.api_url.scheme() == "https" && download_url.scheme() != "https")
            || !download_url.username().is_empty()
            || download_url.password().is_some()
        {
            return Err(UpstreamError::InvalidAttachmentUrl);
        }
        // Blob URLs can point to another host. Never attach the vault's bearer token.
        let mut resp = self
            .client
            .get(download_url)
            .send()
            .await
            .map_err(|e| UpstreamError::RequestFailed(e.without_url()))?;
        if !resp.status().is_success() {
            return Err(UpstreamError::HttpStatusError {
                status: resp.status().as_u16(),
                message: "Attachment download failed".into(),
            });
        }
        if resp
            .content_length()
            .is_some_and(|len| len > MAX_ATTACHMENT_BYTES as u64)
        {
            return Err(UpstreamError::AttachmentTooLarge);
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = resp
            .chunk()
            .await
            .map_err(|e| UpstreamError::RequestFailed(e.without_url()))?
        {
            if chunk.len() > MAX_ATTACHMENT_BYTES - bytes.len() {
                return Err(UpstreamError::AttachmentTooLarge);
            }
            bytes.extend_from_slice(&chunk);
        }
        Ok(bytes)
    }

    /// Calls `POST {identity}/accounts/prelogin` to fetch KDF configuration for an email.
    pub async fn prelogin(&self, email: &str) -> Result<PreloginResponse, UpstreamError> {
        let url = self.endpoints.prelogin_url()?;
        let body = PreloginRequest {
            email: email.to_string(),
        };

        let resp = self.client.post(url).json(&body).send().await?;
        let status = resp.status();
        if !status.is_success() {
            let error_text = resp.text().await.unwrap_or_default();
            return Err(UpstreamError::HttpStatusError {
                status: status.as_u16(),
                message: error_text,
            });
        }

        let prelogin = resp.json::<PreloginResponse>().await?;
        Ok(prelogin)
    }

    /// Authenticates with `POST {identity}/connect/token` via Resource Owner Password Credentials flow.
    pub async fn login(
        &self,
        email: &str,
        master_password_hash: &str,
        two_factor: Option<TwoFactorCredentials>,
        device_identifier: Option<&str>,
    ) -> Result<TokenResponse, UpstreamError> {
        let url = self.endpoints.token_url()?;
        let mut form = HashMap::new();
        form.insert("grant_type", "password".to_string());
        form.insert("username", email.to_string());
        form.insert("password", master_password_hash.to_string());
        form.insert("scope", "api offline_access".to_string());
        form.insert("client_id", "web".to_string());

        let dev_id = match device_identifier {
            Some(id) if !id.trim().is_empty() => id.trim().to_string(),
            _ => uuid::Uuid::new_v4().to_string(),
        };
        form.insert("deviceType", current_device_type().to_string());
        form.insert("deviceIdentifier", dev_id);
        form.insert("deviceName", "tacet-cli".to_string());

        let provider_str;
        let remember_str;
        if let Some(tf) = two_factor {
            provider_str = tf.provider.to_string();
            remember_str = if tf.remember { "1" } else { "0" }.to_string();
            form.insert("twoFactorProvider", provider_str);
            form.insert("twoFactorToken", tf.token);
            form.insert("twoFactorRemember", remember_str);
        }

        let resp = self.client.post(url).form(&form).send().await?;
        let status = resp.status();

        if status.is_success() {
            let token_resp = resp.json::<TokenResponse>().await?;
            return Ok(token_resp);
        }

        let body_bytes = resp.bytes().await?;
        if status == StatusCode::BAD_REQUEST {
            if let Ok(tf_err) = serde_json::from_slice::<TwoFactorErrorResponse>(&body_bytes) {
                if tf_err.error.as_deref() == Some("invalid_grant")
                    && tf_err
                        .error_description
                        .as_deref()
                        .map(|d| d.to_lowercase().contains("two factor"))
                        .unwrap_or(false)
                {
                    let providers = tf_err
                        .two_factor_providers
                        .unwrap_or_default()
                        .keys()
                        .filter_map(|k| k.parse::<u8>().ok())
                        .collect();
                    return Err(UpstreamError::TwoFactorRequired { providers });
                }
            }
        }

        let error_msg = String::from_utf8_lossy(&body_bytes).to_string();
        Err(UpstreamError::HttpStatusError {
            status: status.as_u16(),
            message: error_msg,
        })
    }

    /// Authenticates with `POST {identity}/connect/token` via OAuth2 Client Credentials grant (API key).
    pub async fn login_api_key(
        &self,
        client_id: &str,
        client_secret: &str,
        device_identifier: Option<&str>,
    ) -> Result<TokenResponse, UpstreamError> {
        let url = self.endpoints.token_url()?;

        let normalized_client_id = normalize_api_client_id(client_id);

        let trimmed_client_secret = client_secret.trim().trim_matches('"').trim_matches('\'');

        let scope = if normalized_client_id.starts_with("organization.") {
            "api.organization"
        } else {
            "api"
        };

        let mut form = HashMap::new();
        form.insert("grant_type", "client_credentials".to_string());
        form.insert("client_id", normalized_client_id);
        form.insert("client_secret", trimmed_client_secret.to_string());
        form.insert("scope", scope.to_string());

        let dev_id = match device_identifier {
            Some(id) if !id.trim().is_empty() => id.trim().to_string(),
            _ => uuid::Uuid::new_v4().to_string(),
        };
        form.insert("deviceType", current_device_type().to_string());
        form.insert("deviceIdentifier", dev_id);
        form.insert("deviceName", "tacet-cli".to_string());

        let resp = self.client.post(url).form(&form).send().await?;
        let status = resp.status();

        if status.is_success() {
            let token_resp = resp.json::<TokenResponse>().await?;
            return Ok(token_resp);
        }

        let body_bytes = resp.bytes().await?;
        let error_msg = String::from_utf8_lossy(&body_bytes).to_string();
        Err(UpstreamError::HttpStatusError {
            status: status.as_u16(),
            message: error_msg,
        })
    }

    /// Refreshes access token via `grant_type=refresh_token`.
    pub async fn refresh_token(&self, refresh_token: &str) -> Result<TokenResponse, UpstreamError> {
        let url = self.endpoints.token_url()?;
        let mut form = HashMap::new();
        form.insert("grant_type", "refresh_token".to_string());
        form.insert("refresh_token", refresh_token.to_string());
        form.insert("client_id", "web".to_string());

        let resp = self.client.post(url).form(&form).send().await?;
        let status = resp.status();
        if !status.is_success() {
            let error_text = resp.text().await.unwrap_or_default();
            return Err(UpstreamError::HttpStatusError {
                status: status.as_u16(),
                message: error_text,
            });
        }

        let token_resp = resp.json::<TokenResponse>().await?;
        Ok(token_resp)
    }

    /// Fetches the encrypted vault contents from `GET {api}/sync`.
    pub async fn sync(&self, access_token: &str) -> Result<SyncResponse, UpstreamError> {
        let url = self.endpoints.sync_url()?;
        let resp = self
            .client
            .get(url)
            .bearer_auth(access_token)
            .send()
            .await?;

        let status = resp.status();
        if !status.is_success() {
            let error_text = resp.text().await.unwrap_or_default();
            return Err(UpstreamError::HttpStatusError {
                status: status.as_u16(),
                message: error_text,
            });
        }

        let sync_resp = resp.json::<SyncResponse>().await?;
        Ok(sync_resp)
    }
}
