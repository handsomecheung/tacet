use crate::daemon::models::{
    AttachmentsResponse, ErrorCode, ErrorResponse, ListResponse, LockResponse, LoginRequest,
    LoginResponse, LogoutResponse, ReadRequest, ReadResponse, ReauthenticateRequest,
    ReauthenticateResponse, ResolveRequest, ResolveResponse, StatusResponse, SyncStatusResponse,
    UnlockRequest, UnlockResponse,
};
use crate::upstream::client::normalize_api_client_id;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::client::conn::http1;
use hyper::{Method, Request, StatusCode};
use hyper_util::rt::TokioIo;
use std::path::{Path, PathBuf};
use thiserror::Error;
use tokio::net::UnixStream;

#[derive(Error, Debug)]
pub enum DaemonClientError {
    #[error("IO error connecting to daemon socket: {0}")]
    Io(#[from] std::io::Error),

    #[error("Hyper error: {0}")]
    Hyper(#[from] hyper::Error),

    #[error("HTTP error: {0}")]
    Http(#[from] hyper::http::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Daemon returned status {status}: {message}")]
    HttpStatus {
        status: StatusCode,
        message: String,
        code: Option<ErrorCode>,
    },
}

#[derive(Clone, Debug)]
pub struct DaemonClient {
    socket_path: PathBuf,
}

impl DaemonClient {
    pub fn new<P: AsRef<Path>>(socket_path: P) -> Self {
        Self {
            socket_path: socket_path.as_ref().to_path_buf(),
        }
    }

    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    pub async fn is_alive(&self) -> bool {
        self.status().await.is_ok()
    }

    async fn send_json<Req: serde::Serialize, Resp: serde::de::DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        body: Option<&Req>,
    ) -> Result<Resp, DaemonClientError> {
        let (_, bytes) = self.send_raw(method, path, body).await?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    async fn send_raw<Req: serde::Serialize>(
        &self,
        method: Method,
        path: &str,
        body: Option<&Req>,
    ) -> Result<(hyper::HeaderMap, Vec<u8>), DaemonClientError> {
        let result = self.send_raw_once(method.clone(), path, body).await;
        if matches!(
            &result,
            Err(DaemonClientError::HttpStatus {
                code: Some(ErrorCode::ReauthenticationRequired),
                ..
            })
        ) && self.try_api_reauthentication().await?
        {
            // Bypass recovery on the retry so repeated authentication failures cannot loop.
            return self.send_raw_once(method, path, body).await;
        }
        result
    }

    async fn try_api_reauthentication(&self) -> Result<bool, DaemonClientError> {
        let client_id = std::env::var("TACET_CLIENT_ID")
            .or_else(|_| std::env::var("BW_CLIENTID"))
            .ok()
            .filter(|value| !value.trim().trim_matches('"').trim_matches('\'').is_empty());
        let client_secret = std::env::var("TACET_CLIENT_SECRET")
            .or_else(|_| std::env::var("BW_CLIENTSECRET"))
            .ok()
            .filter(|value| !value.trim().trim_matches('"').trim_matches('\'').is_empty());
        let (Some(client_id), Some(client_secret)) = (client_id, client_secret) else {
            return Ok(false);
        };
        let request = ReauthenticateRequest {
            client_id,
            client_secret,
        };
        let (_, bytes) = self
            .send_raw_once::<()>(Method::GET, "/v1/status", None)
            .await?;
        let status: StatusResponse = serde_json::from_slice(&bytes)?;
        if status.api_client_id.as_deref()
            != Some(normalize_api_client_id(&request.client_id).as_str())
        {
            return Ok(false);
        }
        let (_, bytes) = self
            .send_raw_once(Method::POST, "/v1/reauthenticate", Some(&request))
            .await?;
        let response: ReauthenticateResponse = serde_json::from_slice(&bytes)?;
        Ok(response.authenticated)
    }

    async fn send_raw_once<Req: serde::Serialize>(
        &self,
        method: Method,
        path: &str,
        body: Option<&Req>,
    ) -> Result<(hyper::HeaderMap, Vec<u8>), DaemonClientError> {
        let stream = UnixStream::connect(&self.socket_path).await?;
        let io = TokioIo::new(stream);
        let (mut sender, conn) = http1::handshake(io).await?;

        tokio::spawn(async move {
            if let Err(err) = conn.await {
                tracing::debug!("Client connection closed: {err}");
            }
        });

        let body_bytes = if let Some(b) = body {
            Bytes::from(serde_json::to_vec(b)?)
        } else {
            Bytes::new()
        };

        let req = Request::builder()
            .method(method)
            .uri(path)
            .header("Host", "localhost")
            .header("Content-Type", "application/json")
            .body(Full::new(body_bytes))?;

        let resp = sender.send_request(req).await?;
        let status = resp.status();
        let headers = resp.headers().clone();
        let resp_bytes = resp.into_body().collect().await?.to_bytes();

        if status.is_success() {
            Ok((headers, resp_bytes.to_vec()))
        } else {
            let (message, code) =
                if let Ok(err_resp) = serde_json::from_slice::<ErrorResponse>(&resp_bytes) {
                    (err_resp.error, err_resp.code)
                } else {
                    (String::from_utf8_lossy(&resp_bytes).to_string(), None)
                };

            Err(DaemonClientError::HttpStatus {
                status,
                message,
                code,
            })
        }
    }

    pub async fn status(&self) -> Result<StatusResponse, DaemonClientError> {
        self.send_json::<(), StatusResponse>(Method::GET, "/v1/status", None)
            .await
    }

    pub async fn login(&self, req: &LoginRequest) -> Result<LoginResponse, DaemonClientError> {
        self.send_json(Method::POST, "/v1/login", Some(req)).await
    }

    pub async fn unlock(&self, master_password: &str) -> Result<UnlockResponse, DaemonClientError> {
        let req = UnlockRequest {
            master_password: master_password.to_string(),
        };
        self.send_json(Method::POST, "/v1/unlock", Some(&req)).await
    }

    pub async fn lock(&self) -> Result<LockResponse, DaemonClientError> {
        self.send_json::<(), LockResponse>(Method::POST, "/v1/lock", None)
            .await
    }

    pub async fn logout(&self) -> Result<LogoutResponse, DaemonClientError> {
        self.send_json::<(), LogoutResponse>(Method::POST, "/v1/logout", None)
            .await
    }

    pub async fn sync(&self) -> Result<SyncStatusResponse, DaemonClientError> {
        self.send_json::<(), SyncStatusResponse>(Method::POST, "/v1/sync", None)
            .await
    }

    /// Resolves fields and attachments as text, downloading attachments as needed.
    pub async fn resolve(&self, uris: Vec<String>) -> Result<ResolveResponse, DaemonClientError> {
        let req = ResolveRequest { uris };
        self.send_json(Method::POST, "/v1/resolve", Some(&req))
            .await
    }

    /// Reads a field or attachment as bytes, retaining the value kind returned by the daemon.
    pub async fn read(&self, uri: &str) -> Result<ReadResponse, DaemonClientError> {
        let (headers, bytes) = self
            .send_raw(
                Method::POST,
                "/v1/read",
                Some(&ReadRequest { uri: uri.into() }),
            )
            .await?;
        Ok(ReadResponse {
            bytes,
            is_attachment: headers
                .get("x-tacet-value-kind")
                .is_some_and(|value| value == "attachment"),
        })
    }

    pub async fn attachments(
        &self,
        item_id: &str,
    ) -> Result<AttachmentsResponse, DaemonClientError> {
        let id = percent_encoding::utf8_percent_encode(item_id, percent_encoding::NON_ALPHANUMERIC);
        self.send_json::<(), AttachmentsResponse>(
            Method::GET,
            &format!("/v1/items/{id}/attachments"),
            None,
        )
        .await
    }

    pub async fn list(
        &self,
        scope: Option<&str>,
        search: Option<&str>,
    ) -> Result<ListResponse, DaemonClientError> {
        let mut params = Vec::new();
        if let Some(s) = scope {
            params.push(format!(
                "scope={}",
                percent_encoding::utf8_percent_encode(s, percent_encoding::NON_ALPHANUMERIC)
            ));
        }
        if let Some(q) = search {
            params.push(format!(
                "search={}",
                percent_encoding::utf8_percent_encode(q, percent_encoding::NON_ALPHANUMERIC)
            ));
        }

        let path = if params.is_empty() {
            "/v1/list".to_string()
        } else {
            format!("/v1/list?{}", params.join("&"))
        };

        self.send_json::<(), ListResponse>(Method::GET, &path, None)
            .await
    }
}
