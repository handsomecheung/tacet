use crate::crypto::cipher_string::parse_rsa_private_key;
use crate::crypto::kdf::{
    derive_master_key, derive_master_password_hash, stretch_master_key, KdfParams,
};
use crate::crypto::symmetric_key::SymmetricKey;
use crate::daemon::models::{
    AttachmentsResponse, ErrorCode, ErrorResponse, ListQuery, ListResponse, LockResponse,
    LoginRequest, LoginResponse, LogoutResponse, ReadRequest, ReauthenticateRequest,
    ReauthenticateResponse, ResolveRequest, ResolveResponse, StatusResponse, SyncStatusResponse,
    UnlockRequest, UnlockResponse,
};
use crate::daemon::state::DaemonState;
use crate::error::{ResolverError, UpstreamError};
use crate::resolver::{ReadTarget, VaultResolver};
use crate::storage::session::SessionMetadata;
use crate::storage::vault_cache::EncryptedVaultCache;
use crate::upstream::client::normalize_api_client_id;
use crate::upstream::models::TwoFactorCredentials;
use crate::upstream::UpstreamClient;
use crate::uri::parser::TacetUri;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{Duration, Utc};
use std::collections::HashMap;

pub fn create_router(state: DaemonState) -> Router {
    Router::new()
        .route("/v1/status", get(status_handler))
        .route("/v1/login", post(login_handler))
        .route("/v1/reauthenticate", post(reauthenticate_handler))
        .route("/v1/unlock", post(unlock_handler))
        .route("/v1/lock", post(lock_handler))
        .route("/v1/logout", post(logout_handler))
        .route("/v1/sync", post(sync_handler))
        .route("/v1/resolve", post(resolve_handler))
        .route("/v1/read", post(read_handler))
        .route("/v1/items/{item_id}/attachments", get(attachments_handler))
        .route("/v1/list", get(list_handler))
        .with_state(state)
}

async fn status_handler(State(state): State<DaemonState>) -> impl IntoResponse {
    state.touch_activity();

    let logged_in = state.is_logged_in().await;
    let unlocked = state.is_unlocked().await;
    let server_url = state.server_url().await;
    let item_count = state.item_count().await;
    let api_client_id = state
        .session
        .read()
        .await
        .as_ref()
        .and_then(|s| s.api_client_id.clone());

    Json(StatusResponse {
        running: true,
        logged_in,
        unlocked,
        server_url,
        api_client_id,
        item_count,
    })
}

async fn login_handler(
    State(state): State<DaemonState>,
    Json(req): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, (StatusCode, Json<ErrorResponse>)> {
    state.touch_activity();

    // 1. Build upstream client
    let client = UpstreamClient::new(&req.server_url).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new(e.to_string())),
        )
    })?;

    let device_id = state.storage_paths.get_or_create_device_id().map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse::new(e.to_string())),
        )
    })?;

    let is_api_key_login = req.client_id.is_some() && req.client_secret.is_some();

    if is_api_key_login {
        let client_id = req.client_id.as_deref().unwrap();
        let client_secret = req.client_secret.as_deref().unwrap();

        let token_resp = client
            .login_api_key(client_id, client_secret, Some(&device_id))
            .await
            .map_err(|e| {
                (
                    StatusCode::UNAUTHORIZED,
                    Json(ErrorResponse::new(e.to_string())),
                )
            })?;

        // Initial Sync to retrieve profile (email, protected keys) and vault ciphers
        let sync_resp = client.sync(&token_resp.access_token).await.map_err(|e| {
            (
                StatusCode::BAD_GATEWAY,
                Json(ErrorResponse::new(e.to_string())),
            )
        })?;

        let email = match req
            .email
            .as_deref()
            .or_else(|| sync_resp.profile.as_ref().map(|p| p.email.as_str()))
        {
            Some(e) if !e.trim().is_empty() => e.trim().to_string(),
            _ => {
                return Err((
                    StatusCode::BAD_GATEWAY,
                    Json(ErrorResponse::new(
                        "API key authentication succeeded, but could not determine user email from vault profile. Please provide email explicitly.",
                    )),
                ));
            }
        };

        let prelogin = client.prelogin(&email).await.map_err(|e| {
            (
                StatusCode::BAD_GATEWAY,
                Json(ErrorResponse::new(e.to_string())),
            )
        })?;

        let kdf_params = match prelogin.kdf {
            1 => KdfParams::argon2id(
                prelogin.kdf_iterations,
                prelogin.kdf_memory.unwrap_or(64),
                prelogin.kdf_parallelism.unwrap_or(4),
            ),
            _ => KdfParams::pbkdf2(prelogin.kdf_iterations),
        };

        let protected_key = sync_resp.profile.as_ref().and_then(|p| p.key.clone());
        let protected_rsa_private_key = sync_resp
            .profile
            .as_ref()
            .and_then(|p| p.private_key.clone());

        let (sym_key, rsa_priv, unlocked) = if let Some(master_pwd) = &req.master_password {
            if !master_pwd.is_empty() {
                let prot_key_str = protected_key.as_deref().ok_or_else(|| {
                    (
                        StatusCode::BAD_GATEWAY,
                        Json(ErrorResponse::new(
                            "Server did not return account key in profile",
                        )),
                    )
                })?;

                let master_key =
                    derive_master_key(master_pwd, &email, &kdf_params).map_err(|e| {
                        (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            Json(ErrorResponse::new(e.to_string())),
                        )
                    })?;

                let stretched = stretch_master_key(&master_key).map_err(|e| {
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(ErrorResponse::new(e.to_string())),
                    )
                })?;

                let sk =
                    SymmetricKey::from_protected_key(prot_key_str, &stretched).map_err(|_| {
                        (
                            StatusCode::UNAUTHORIZED,
                            Json(ErrorResponse::new("Invalid master password")),
                        )
                    })?;

                let rsa = if let Some(pk_str) = &protected_rsa_private_key {
                    if let Ok(raw_pk) = sk.decrypt_type2(pk_str) {
                        parse_rsa_private_key(&raw_pk).ok()
                    } else {
                        None
                    }
                } else {
                    None
                };

                (Some(sk), rsa, true)
            } else {
                (None, None, false)
            }
        } else {
            (None, None, false)
        };

        let expires_at = Utc::now() + Duration::seconds(token_resp.expires_in as i64);

        let session_meta = SessionMetadata {
            server_url: req.server_url.clone(),
            email: email.clone(),
            api_client_id: Some(normalize_api_client_id(client_id)),
            access_token: token_resp.access_token.clone(),
            refresh_token: token_resp.refresh_token.clone(),
            expires_at: Some(expires_at),
            kdf_params,
            protected_symmetric_key: protected_key,
            protected_rsa_private_key,
            user_id: sync_resp.profile.as_ref().map(|p| p.id.clone()),
            last_synced: Some(Utc::now()),
        };

        session_meta.save(&state.storage_paths).map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse::new(format!(
                    "Failed to persist session: {e}"
                ))),
            )
        })?;

        let vault_cache = EncryptedVaultCache::new(sync_resp.clone());
        vault_cache.save(&state.storage_paths).map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse::new(format!(
                    "Failed to persist vault cache: {e}"
                ))),
            )
        })?;

        let item_count = sync_resp.ciphers.len() as u32;

        *state.session.write().await = Some(session_meta);
        *state.vault.write().await = Some(sync_resp);
        *state.symmetric_key.write().await = sym_key;
        *state.rsa_private_key.write().await = rsa_priv;
        *state.upstream_client.write().await = Some(client);

        return Ok(Json(LoginResponse {
            unlocked,
            item_count,
        }));
    }

    // Password login flow
    let email = req.email.as_deref().ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new("Password login requires 'email'")),
        )
    })?;

    let master_password = req.master_password.as_deref().ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new(
                "Password login requires 'master_password'",
            )),
        )
    })?;

    // 2. Prelogin to obtain KDF parameters
    let prelogin = client.prelogin(email).await.map_err(|e| {
        (
            StatusCode::BAD_GATEWAY,
            Json(ErrorResponse::new(e.to_string())),
        )
    })?;

    let kdf_params = match prelogin.kdf {
        1 => KdfParams::argon2id(
            prelogin.kdf_iterations,
            prelogin.kdf_memory.unwrap_or(64),
            prelogin.kdf_parallelism.unwrap_or(4),
        ),
        _ => KdfParams::pbkdf2(prelogin.kdf_iterations),
    };

    // 3. Derive keys
    let master_key = derive_master_key(master_password, email, &kdf_params).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse::new(e.to_string())),
        )
    })?;

    let master_password_hash =
        derive_master_password_hash(&master_key, master_password).map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse::new(e.to_string())),
            )
        })?;

    let two_factor = req.two_factor_token.map(|tok| TwoFactorCredentials {
        provider: req.two_factor_provider.unwrap_or(0),
        token: tok,
        remember: true,
    });

    // 4. Authenticate upstream
    let token_resp = client
        .login(email, &master_password_hash, two_factor, Some(&device_id))
        .await
        .map_err(|e| {
            (
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse::new(e.to_string())),
            )
        })?;

    // 5. Derive symmetric key
    let stretched = stretch_master_key(&master_key).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse::new(e.to_string())),
        )
    })?;

    let protected_key = token_resp.key.as_deref().ok_or_else(|| {
        (
            StatusCode::BAD_GATEWAY,
            Json(ErrorResponse::new("Server did not return account key")),
        )
    })?;

    let sym_key = SymmetricKey::from_protected_key(protected_key, &stretched).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse::new(e.to_string())),
        )
    })?;

    // Decrypt RSA private key if available
    let rsa_priv = if let Some(pk_str) = &token_resp.private_key {
        if let Ok(raw_pk) = sym_key.decrypt_type2(pk_str) {
            parse_rsa_private_key(&raw_pk).ok()
        } else {
            None
        }
    } else {
        None
    };

    // 6. Initial Sync
    let sync_resp = client.sync(&token_resp.access_token).await.map_err(|e| {
        (
            StatusCode::BAD_GATEWAY,
            Json(ErrorResponse::new(e.to_string())),
        )
    })?;

    let expires_at = Utc::now() + Duration::seconds(token_resp.expires_in as i64);

    let session_meta = SessionMetadata {
        server_url: req.server_url.clone(),
        email: email.to_string(),
        api_client_id: None,
        access_token: token_resp.access_token.clone(),
        refresh_token: token_resp.refresh_token.clone(),
        expires_at: Some(expires_at),
        kdf_params,
        protected_symmetric_key: token_resp.key.clone(),
        protected_rsa_private_key: token_resp.private_key.clone(),
        user_id: sync_resp.profile.as_ref().map(|p| p.id.clone()),
        last_synced: Some(Utc::now()),
    };

    // 7. Persist to storage
    session_meta.save(&state.storage_paths).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse::new(format!(
                "Failed to persist session: {e}"
            ))),
        )
    })?;

    let vault_cache = EncryptedVaultCache::new(sync_resp.clone());
    vault_cache.save(&state.storage_paths).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse::new(format!(
                "Failed to persist vault cache: {e}"
            ))),
        )
    })?;

    let item_count = sync_resp.ciphers.len() as u32;

    // 8. Update in-memory state
    *state.session.write().await = Some(session_meta);
    *state.vault.write().await = Some(sync_resp);
    *state.symmetric_key.write().await = Some(sym_key);
    *state.rsa_private_key.write().await = rsa_priv;
    *state.upstream_client.write().await = Some(client);

    Ok(Json(LoginResponse {
        unlocked: true,
        item_count,
    }))
}

async fn reauthenticate_handler(
    State(state): State<DaemonState>,
    Json(req): Json<ReauthenticateRequest>,
) -> Result<Json<ReauthenticateResponse>, ApiError> {
    state.touch_activity();
    let mut guard = state.session.write().await;
    let session = guard
        .as_ref()
        .ok_or_else(|| api_error(StatusCode::UNAUTHORIZED, "Not logged in"))?;
    if session.api_client_id.as_deref() != Some(normalize_api_client_id(&req.client_id).as_str()) {
        return Err(api_error(
            StatusCode::BAD_REQUEST,
            "API credentials do not match the current API-key session",
        ));
    }
    let client = UpstreamClient::new(&session.server_url)
        .map_err(|e| api_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let device_id = state
        .storage_paths
        .get_or_create_device_id()
        .map_err(|e| api_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let response = client
        .login_api_key(&req.client_id, &req.client_secret, Some(&device_id))
        .await
        .map_err(|e| match e {
            UpstreamError::HttpStatusError {
                status: 400 | 401, ..
            } => api_error(
                StatusCode::UNAUTHORIZED,
                "API-key reauthentication failed: credentials were rejected",
            ),
            _ => api_error(
                StatusCode::BAD_GATEWAY,
                "API-key reauthentication failed: vault server unavailable",
            ),
        })?;
    let mut renewed = session.clone();
    renewed.access_token = response.access_token;
    renewed.refresh_token = response.refresh_token;
    renewed.expires_at = Some(Utc::now() + Duration::seconds(response.expires_in as i64));
    renewed
        .save(&state.storage_paths)
        .map_err(|e| api_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    *guard = Some(renewed);
    Ok(Json(ReauthenticateResponse {
        authenticated: true,
    }))
}

async fn unlock_handler(
    State(state): State<DaemonState>,
    Json(req): Json<UnlockRequest>,
) -> Result<Json<UnlockResponse>, (StatusCode, Json<ErrorResponse>)> {
    state.touch_activity();

    // 1. Ensure logged in (from memory or disk)
    let session = {
        let guard = state.session.read().await;
        if let Some(s) = guard.as_ref() {
            s.clone()
        } else {
            SessionMetadata::load(&state.storage_paths).map_err(|_| {
                (
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse::new(
                        "Not logged in. Run 'tacet login' first.",
                    )),
                )
            })?
        }
    };

    let protected_key = session.protected_symmetric_key.as_deref().ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new("Session metadata missing protected key")),
        )
    })?;

    // 2. Derive master key from cached KDF parameters
    let master_key = derive_master_key(&req.master_password, &session.email, &session.kdf_params)
        .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse::new(e.to_string())),
        )
    })?;

    let stretched = stretch_master_key(&master_key).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse::new(e.to_string())),
        )
    })?;

    // 3. Decrypt protected symmetric key (constant-time verification)
    let sym_key = SymmetricKey::from_protected_key(protected_key, &stretched).map_err(|_| {
        (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse::new("Invalid master password")),
        )
    })?;

    // Decrypt RSA private key if present
    let rsa_priv = if let Some(pk_str) = &session.protected_rsa_private_key {
        if let Ok(raw_pk) = sym_key.decrypt_type2(pk_str) {
            parse_rsa_private_key(&raw_pk).ok()
        } else {
            None
        }
    } else {
        None
    };

    // Ensure vault cache is loaded
    {
        let mut vault_guard = state.vault.write().await;
        if vault_guard.is_none() {
            if let Ok(cache) = EncryptedVaultCache::load(&state.storage_paths) {
                *vault_guard = Some(cache.data);
            }
        }
    }

    *state.session.write().await = Some(session);
    *state.symmetric_key.write().await = Some(sym_key);
    *state.rsa_private_key.write().await = rsa_priv;

    Ok(Json(UnlockResponse { unlocked: true }))
}

async fn lock_handler(State(state): State<DaemonState>) -> impl IntoResponse {
    state.lock().await;
    Json(LockResponse { locked: true })
}

async fn logout_handler(State(state): State<DaemonState>) -> impl IntoResponse {
    state.lock().await;

    *state.session.write().await = None;
    *state.vault.write().await = None;
    *state.upstream_client.write().await = None;

    let _ = SessionMetadata::clear(&state.storage_paths);
    let _ = EncryptedVaultCache::clear(&state.storage_paths);

    Json(LogoutResponse { logged_out: true })
}

async fn sync_handler(
    State(state): State<DaemonState>,
) -> Result<Json<SyncStatusResponse>, (StatusCode, Json<ErrorResponse>)> {
    state.touch_activity();

    let (client, snapshot) = upstream_session(&state).await?;
    let sync_resp = client.sync(&snapshot.access_token).await.map_err(|e| {
        if matches!(e, UpstreamError::HttpStatusError { status: 401, .. }) {
            reauthentication_required("Session rejected by server. Run 'tacet login' again.")
        } else {
            api_error(StatusCode::BAD_GATEWAY, format!("Sync failed: {e}"))
        }
    })?;
    let item_count = sync_resp.ciphers.len() as u32;

    let mut guard = state.session.write().await;
    let session = guard
        .as_mut()
        .ok_or_else(|| api_error(StatusCode::CONFLICT, "Session changed during sync"))?;
    if session.server_url != snapshot.server_url
        || session.user_id != snapshot.user_id
        || session.api_client_id != snapshot.api_client_id
        || session.email != snapshot.email
    {
        return Err(api_error(
            StatusCode::CONFLICT,
            "Session changed during sync",
        ));
    }
    let cache = EncryptedVaultCache::new(sync_resp.clone());
    cache
        .save(&state.storage_paths)
        .map_err(|e| api_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    session.last_synced = Some(Utc::now());
    session
        .save(&state.storage_paths)
        .map_err(|e| api_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    *state.vault.write().await = Some(sync_resp);

    Ok(Json(SyncStatusResponse {
        synced: true,
        item_count,
    }))
}

async fn resolve_handler(
    State(state): State<DaemonState>,
    Json(req): Json<ResolveRequest>,
) -> Result<Json<ResolveResponse>, (StatusCode, Json<ErrorResponse>)> {
    state.touch_activity();

    // 1. Vault must be unlocked
    let sym_key_guard = state.symmetric_key.read().await;
    let sym_key = sym_key_guard.as_ref().ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse::new(
                "Vault is locked. Run 'tacet unlock' first.",
            )),
        )
    })?;

    // 2. Vault data must be present
    let vault_guard = state.vault.read().await;
    let vault = vault_guard.as_ref().ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new("Vault cache is empty. Please run sync.")),
        )
    })?;

    let rsa_guard = state.rsa_private_key.read().await;
    let resolver = VaultResolver::new(vault, sym_key, rsa_guard.as_ref());

    let mut secrets = HashMap::new();
    for uri_str in &req.uris {
        let parsed_uri = TacetUri::parse(uri_str).map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse::new(format!("Invalid URI '{uri_str}': {e}"))),
            )
        })?;

        let value = resolver.resolve(&parsed_uri).map_err(resolver_response)?;
        secrets.insert(uri_str.clone(), value);
    }

    Ok(Json(ResolveResponse { secrets }))
}

type ApiError = (StatusCode, Json<ErrorResponse>);

fn api_error(status: StatusCode, message: impl Into<String>) -> ApiError {
    (status, Json(ErrorResponse::new(message)))
}

fn reauthentication_required(message: &str) -> ApiError {
    (
        StatusCode::UNAUTHORIZED,
        Json(ErrorResponse {
            error: message.into(),
            code: Some(ErrorCode::ReauthenticationRequired),
        }),
    )
}

fn resolver_response(error: ResolverError) -> ApiError {
    let status = match &error {
        ResolverError::ItemNotFound { .. }
        | ResolverError::FieldNotFound { .. }
        | ResolverError::AttachmentNotFound { .. }
        | ResolverError::FolderNotFound { .. }
        | ResolverError::OrganizationNotFound { .. }
        | ResolverError::CollectionNotFound { .. } => StatusCode::NOT_FOUND,
        ResolverError::AmbiguousMatch { .. } | ResolverError::AmbiguousAttachment { .. } => {
            StatusCode::CONFLICT
        }
        ResolverError::AttachmentRequiresRead
        | ResolverError::InvalidAttachmentModifier
        | ResolverError::JsonPathError(_) => StatusCode::BAD_REQUEST,
        ResolverError::Crypto(_) => StatusCode::BAD_GATEWAY,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    };
    api_error(status, error.to_string())
}

fn read_response(bytes: Vec<u8>, attachment: bool, encoded: bool) -> axum::response::Response {
    let content_type = if attachment && !encoded {
        "application/octet-stream"
    } else {
        "text/plain; charset=utf-8"
    };
    (
        [
            ("content-type", content_type),
            ("cache-control", "no-store"),
            (
                "x-tacet-value-kind",
                if attachment { "attachment" } else { "field" },
            ),
        ],
        bytes,
    )
        .into_response()
}

async fn read_handler(
    State(state): State<DaemonState>,
    Json(req): Json<ReadRequest>,
) -> Result<axum::response::Response, ApiError> {
    state.touch_activity();
    let uri =
        TacetUri::parse(&req.uri).map_err(|e| api_error(StatusCode::BAD_REQUEST, e.to_string()))?;
    let selected = {
        let key_guard = state.symmetric_key.read().await;
        let key = key_guard.as_ref().ok_or_else(|| {
            api_error(
                StatusCode::UNAUTHORIZED,
                "Vault is locked. Run 'tacet unlock' first.",
            )
        })?;
        let vault_guard = state.vault.read().await;
        let vault = vault_guard.as_ref().ok_or_else(|| {
            api_error(
                StatusCode::BAD_REQUEST,
                "Vault cache is empty. Please run sync.",
            )
        })?;
        let rsa_guard = state.rsa_private_key.read().await;
        let resolver = VaultResolver::new(vault, key, rsa_guard.as_ref());
        match resolver.select_read(&uri).map_err(resolver_response)? {
            ReadTarget::Text(value) => return Ok(read_response(value.into_bytes(), false, false)),
            ReadTarget::Attachment(selected) => selected,
        }
    };
    // Release key guards before network IO so locking remains immediate during downloads.
    let (client, session) = upstream_session(&state).await?;
    let encrypted = client
        .download_attachment(
            &session.access_token,
            &selected.cipher_id,
            &selected.attachment.id,
            selected.attachment.url.as_deref(),
        )
        .await
        .map_err(|e| {
            if matches!(e, UpstreamError::AuthenticationFailed(_)) {
                return reauthentication_required(
                    "Session rejected by server. Run 'tacet login' again.",
                );
            }
            let status = match &e {
                UpstreamError::AttachmentTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
                UpstreamError::HttpStatusError { status: 404, .. } => StatusCode::NOT_FOUND,
                _ => StatusCode::BAD_GATEWAY,
            };
            api_error(status, e.to_string())
        })?;
    let key_guard = state.symmetric_key.read().await;
    let key = key_guard.as_ref().ok_or_else(|| {
        api_error(
            StatusCode::UNAUTHORIZED,
            "Vault was locked during attachment download",
        )
    })?;
    let vault_guard = state.vault.read().await;
    let vault = vault_guard
        .as_ref()
        .ok_or_else(|| api_error(StatusCode::UNAUTHORIZED, "Vault is unavailable"))?;
    let rsa_guard = state.rsa_private_key.read().await;
    let resolver = VaultResolver::new(vault, key, rsa_guard.as_ref());
    let bytes = resolver
        .decrypt_attachment(&selected, &encrypted, &uri)
        .map_err(resolver_response)?;
    state.touch_activity();
    Ok(read_response(bytes, true, uri.modifiers.encoding.is_some()))
}

async fn upstream_session(
    state: &DaemonState,
) -> Result<(UpstreamClient, SessionMetadata), ApiError> {
    let client = state
        .upstream_client
        .read()
        .await
        .clone()
        .ok_or_else(|| api_error(StatusCode::UNAUTHORIZED, "Not logged in"))?;
    let mut guard = state.session.write().await;
    let session = guard
        .as_mut()
        .ok_or_else(|| api_error(StatusCode::UNAUTHORIZED, "Not logged in"))?;
    if session
        .expires_at
        .is_some_and(|expiry| expiry <= Utc::now() + Duration::seconds(60))
    {
        let refresh = session.refresh_token.as_ref().ok_or_else(|| {
            reauthentication_required("Session expired. Run 'tacet login' again.")
        })?;
        let response = client.refresh_token(refresh).await.map_err(|e| {
            if matches!(
                e,
                UpstreamError::HttpStatusError {
                    status: 400 | 401,
                    ..
                }
            ) {
                reauthentication_required("Session refresh failed. Run 'tacet login' again.")
            } else {
                api_error(
                    StatusCode::BAD_GATEWAY,
                    format!("Session refresh failed: {e}"),
                )
            }
        })?;
        session.access_token = response.access_token;
        if let Some(refresh) = response.refresh_token {
            session.refresh_token = Some(refresh);
        }
        session.expires_at = Some(Utc::now() + Duration::seconds(response.expires_in as i64));
        session
            .save(&state.storage_paths)
            .map_err(|e| api_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    }
    Ok((client, session.clone()))
}

async fn attachments_handler(
    State(state): State<DaemonState>,
    Path(item_id): Path<String>,
) -> Result<Json<AttachmentsResponse>, ApiError> {
    state.touch_activity();
    if uuid::Uuid::parse_str(&item_id).is_err() {
        return Err(api_error(StatusCode::BAD_REQUEST, "Expected an item UUID"));
    }
    let key_guard = state.symmetric_key.read().await;
    let key = key_guard
        .as_ref()
        .ok_or_else(|| api_error(StatusCode::UNAUTHORIZED, "Vault is locked"))?;
    let vault_guard = state.vault.read().await;
    let vault = vault_guard
        .as_ref()
        .ok_or_else(|| api_error(StatusCode::BAD_REQUEST, "Vault cache is empty"))?;
    let rsa_guard = state.rsa_private_key.read().await;
    let resolver = VaultResolver::new(vault, key, rsa_guard.as_ref());
    Ok(Json(AttachmentsResponse {
        attachments: resolver
            .list_attachments(&item_id)
            .map_err(resolver_response)?,
    }))
}

async fn list_handler(
    State(state): State<DaemonState>,
    Query(query): Query<ListQuery>,
) -> Result<Json<ListResponse>, (StatusCode, Json<ErrorResponse>)> {
    state.touch_activity();

    // 1. Vault must be unlocked
    let sym_key_guard = state.symmetric_key.read().await;
    let sym_key = sym_key_guard.as_ref().ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse::new(
                "Vault is locked. Run 'tacet unlock' first.",
            )),
        )
    })?;

    // 2. Vault data must be present
    let vault_guard = state.vault.read().await;
    let vault = vault_guard.as_ref().ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new("Vault cache is empty. Please run sync.")),
        )
    })?;

    let rsa_guard = state.rsa_private_key.read().await;
    let resolver = VaultResolver::new(vault, sym_key, rsa_guard.as_ref());

    let items = resolver
        .list_items(query.scope.as_deref(), query.search.as_deref())
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse::new(format!("Failed to list items: {e}"))),
            )
        })?;

    let total = items.len();
    Ok(Json(ListResponse { items, total }))
}
