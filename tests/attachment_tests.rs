use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use std::path::PathBuf;
use std::time::Duration;
use tacet::crypto::{cipher_string::CipherString, symmetric_key::SymmetricKey};
use tacet::daemon::{bind_unix_socket, run_server, DaemonClient, DaemonClientError, DaemonState};
use tacet::error::{CryptoError, ResolverError, UpstreamError};
use tacet::resolver::{ReadTarget, VaultResolver};
use tacet::storage::{session::SessionMetadata, StoragePaths};
use tacet::upstream::models::{
    AttachmentResponse, CipherFieldResponse, CipherLoginResponse, CipherResponse,
    CollectionResponse, ProfileOrganizationResponse, ProfileResponse, SyncResponse,
};
use tacet::upstream::UpstreamClient;
use tacet::uri::parser::{CipherFieldTarget, Scope, TacetUri};
use tempfile::{tempdir, TempDir};
use tokio::sync::broadcast;
use wiremock::matchers::{bearer_token, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const ITEM_ID: &str = "12345678-1234-1234-1234-123456789abc";
const ORIGINAL: &[u8] = b" \tMZ\0\xff\xfe\x80\r\n\n ";

fn blob(key: &SymmetricKey, plaintext: &[u8]) -> Vec<u8> {
    let encrypted = key.encrypt_type2(plaintext).unwrap();
    let CipherString::Type2 { iv, ct, mac } = CipherString::parse(&encrypted).unwrap() else {
        panic!("Expected Type 2");
    };
    [vec![2], iv, mac, ct].concat()
}

fn vault(user: &SymmetricKey, item: &SymmetricKey, content: &SymmetricKey) -> SyncResponse {
    SyncResponse {
        ciphers: vec![CipherResponse {
            deleted_date: None,
            id: ITEM_ID.into(),
            organization_id: None,
            folder_id: None,
            collection_ids: vec![],
            cipher_type: 1,
            name: item.encrypt_type2_string("Server").unwrap(),
            key: Some(user.encrypt_type2(item.as_bytes()).unwrap()),
            notes: None,
            favorite: None,
            login: Some(CipherLoginResponse {
                password: Some(item.encrypt_type2_string("field-password").unwrap()),
                ..Default::default()
            }),
            fields: Some(vec![CipherFieldResponse {
                name: Some(item.encrypt_type2_string("config.yml").unwrap()),
                value: Some(item.encrypt_type2_string("").unwrap()),
                field_type: Some(0),
            }]),
            attachments: Some(
                [
                    "example.exe",
                    "config.yml",
                    "password",
                    "duplicate",
                    "duplicate",
                    "Password",
                ]
                .iter()
                .enumerate()
                .map(|(index, name)| AttachmentResponse {
                    id: format!("attachment-{index}"),
                    file_name: item.encrypt_type2_string(name).unwrap(),
                    key: Some(item.encrypt_type2(content.as_bytes()).unwrap()),
                    url: None,
                })
                .collect(),
            ),
        }],
        ..Default::default()
    }
}

#[test]
fn attachment_uri_paths_and_escaped_names() {
    for (uri, expected_item, expected_name) in [
        (
            "tacet://personal/Server/files/example.exe",
            "Server",
            "example.exe",
        ),
        (
            "tacet://personal/Work/Infra/Server/files/a%2Fb%3Fc%23d",
            "Server",
            "a/b?c#d",
        ),
        (
            "tacet://org/Engineering/Infra/Production/Server/files/config.yml",
            "Server",
            "config.yml",
        ),
        (
            "tacet://*/Server/files/example.exe",
            "Server",
            "example.exe",
        ),
        (
            "tacet://personal/Server/files/fields%2Fname",
            "Server",
            "fields/name",
        ),
    ] {
        let parsed = TacetUri::parse(uri).unwrap();
        assert_eq!(parsed.item, expected_item);
        assert_eq!(parsed.field, CipherFieldTarget::File(expected_name.into()));
    }
    let uri = TacetUri::parse("tacet://personal/Server/files%2Fconfig.yml").unwrap();
    assert_eq!(
        uri.field,
        CipherFieldTarget::Named("files/config.yml".into())
    );
    let uri = TacetUri::parse("tacet://personal/Server/fields/files").unwrap();
    assert_eq!(uri.field, CipherFieldTarget::CustomField("files".into()));
    assert_eq!(
        TacetUri::parse("tacet://*/Server/files/config.yml")
            .unwrap()
            .scope,
        Scope::All
    );
    assert!(TacetUri::parse("tacet://org/Engineering/Server/files/config.yml").is_err());
}

#[test]
fn field_precedence_ambiguity_and_modifiers() {
    let user = SymmetricKey::new([10; 64]);
    let item = SymmetricKey::new([20; 64]);
    let content = SymmetricKey::new([30; 64]);
    let mut data = vault(&user, &item, &content);
    {
        let resolver = VaultResolver::new(&data, &user, None);
        for (target, expected) in [("password", "field-password"), ("config.yml", "")] {
            assert_eq!(
                resolver
                    .resolve_str(&format!("tacet://personal/Server/{target}"))
                    .unwrap(),
                expected
            );
        }
        for target in [
            "example.exe",
            "files/config.yml",
            "files/password",
            "files/attachment-0",
        ] {
            assert!(matches!(
                resolver
                    .select_read(
                        &TacetUri::parse(&format!("tacet://personal/Server/{target}")).unwrap()
                    )
                    .unwrap(),
                ReadTarget::Attachment(_)
            ));
        }
        assert!(
            matches!(resolver.select_read(&TacetUri::parse("tacet://personal/Server/duplicate").unwrap()), Err(ResolverError::AmbiguousAttachment { matches, .. }) if matches.contains("attachment-3") && matches.contains("attachment-4"))
        );
        assert!(matches!(
            resolver.select_read(&TacetUri::parse("tacet://personal/Server/EXAMPLE.EXE").unwrap()),
            Err(ResolverError::FieldNotFound { .. })
        ));
        assert!(matches!(
            resolver.select_read(
                &TacetUri::parse("tacet://personal/Server/fields/example.exe").unwrap()
            ),
            Err(ResolverError::FieldNotFound { .. })
        ));
        assert!(matches!(
            resolver.resolve(&TacetUri::parse("tacet://personal/Server/example.exe").unwrap()),
            Err(ResolverError::AttachmentRequiresRead)
        ));
        for query in ["trim=true", "trim=false", "json=x"] {
            assert!(matches!(
                resolver.select_read(
                    &TacetUri::parse(&format!("tacet://personal/Server/example.exe?{query}"))
                        .unwrap()
                ),
                Err(ResolverError::InvalidAttachmentModifier)
            ));
        }
    }
    data.ciphers[0].login.as_mut().unwrap().password = Some("invalid-encrypted-field".into());
    let resolver = VaultResolver::new(&data, &user, None);
    assert!(matches!(
        resolver.select_read(&TacetUri::parse("tacet://personal/Server/password").unwrap()),
        Err(ResolverError::Crypto(_))
    ));
    data.ciphers[0].login.as_mut().unwrap().password = None;
    let resolver = VaultResolver::new(&data, &user, None);
    let ReadTarget::Attachment(selected) = resolver
        .select_read(&TacetUri::parse("tacet://personal/Server/Password").unwrap())
        .unwrap()
    else {
        panic!("Expected exact filename fallback")
    };
    assert_eq!(selected.attachment.id, "attachment-5");
}

#[test]
fn attachment_key_versions_and_organization_scope() {
    let user = SymmetricKey::new([10; 64]);
    let item = SymmetricKey::new([20; 64]);
    let content = SymmetricKey::new([30; 64]);
    let org = SymmetricKey::new([40; 64]);
    for version in 1..=3 {
        for organization in [false, true] {
            let owner = if organization { &org } else { &user };
            let item_key = if version == 3 { &item } else { owner };
            let content_key = if version == 1 { owner } else { &content };
            let mut data = vault(owner, item_key, &content);
            data.ciphers[0].login = None;
            data.ciphers[0].fields = None;
            data.ciphers[0].notes = None;
            if version < 3 {
                data.ciphers[0].key = None;
            }
            if version == 1 {
                data.ciphers[0].attachments.as_mut().unwrap()[0].key = None;
            }
            if organization {
                data.ciphers[0].organization_id = Some("org-id".into());
                data.ciphers[0].collection_ids = vec!["collection-id".into()];
                data.profile = Some(ProfileResponse {
                    id: "user".into(),
                    name: None,
                    email: "u@example.com".into(),
                    key: None,
                    private_key: None,
                    organizations: vec![ProfileOrganizationResponse {
                        id: "org-id".into(),
                        name: "Engineering".into(),
                        key: Some(user.encrypt_type2(org.as_bytes()).unwrap()),
                    }],
                });
                data.collections = vec![CollectionResponse {
                    id: "collection-id".into(),
                    organization_id: "org-id".into(),
                    name: org.encrypt_type2_string("Infra/Production").unwrap(),
                }];
            }
            let prefix = if organization {
                "tacet://org/Engineering/Infra/Production/Server"
            } else {
                "tacet://personal/Server"
            };
            let resolver = VaultResolver::new(&data, &user, None);
            let listed = resolver.list_items(None, None).unwrap();
            assert_eq!(listed.len(), 1);
            assert_eq!(listed[0].id, ITEM_ID);
            for (query, expected) in [
                ("", ORIGINAL.to_vec()),
                ("?encoding=base64", BASE64.encode(ORIGINAL).into_bytes()),
                (
                    "?encoding=hex",
                    ORIGINAL
                        .iter()
                        .map(|b| format!("{b:02x}"))
                        .collect::<String>()
                        .into_bytes(),
                ),
            ] {
                let uri = TacetUri::parse(&format!("{prefix}/example.exe{query}")).unwrap();
                let ReadTarget::Attachment(selected) = resolver.select_read(&uri).unwrap() else {
                    panic!("Expected attachment")
                };
                let encrypted = blob(content_key, ORIGINAL);
                assert_eq!(
                    resolver
                        .decrypt_attachment(&selected, &encrypted, &uri)
                        .unwrap(),
                    expected
                );
                let mut tampered = encrypted;
                tampered[17] ^= 1;
                assert!(matches!(
                    resolver.decrypt_attachment(&selected, &tampered, &uri),
                    Err(ResolverError::Crypto(CryptoError::MacVerificationFailed))
                ));
            }
        }
    }
}

#[test]
fn bitwarden_attachment_interoperability_vector() {
    // Fixture from bitwarden/sdk-internal, crates/bitwarden-vault/src/cipher/attachment.rs,
    // test_attachment_without_key. This checks the wire format independently of our encoder.
    let key = SymmetricKey::from_slice(&BASE64.decode("w2LO+nwV4oxwswVYCxlOfRUseXfvU03VzvKQHrqeklPgiMZrspUe6sOBToCnDn9Ay0tuCBn8ykVVRb7PWhub2Q==").unwrap()).unwrap();
    let encrypted = BASE64.decode("AsQLXOBHrJ8porroTUlPxeJOm9XID7LL9D2+KwYATXEpR1EFjLBpcCvMmnqcnYLXIEefe9TCeY4Us50ux43kRSpvdB7YkjxDKV0O1/y6tB7qC4vvv9J9+O/uDEnMx/9yXuEhAW/LA/TsU/WAgxkOM0uTvm8JdD9LUR1z9Ql7zOWycMVzkvGsk2KBNcqAdrotS5FlDftZOXyU8pWecNeyA/w=").unwrap();
    let expected = BASE64.decode("rMweTemxOL9D0iWWfRxiY3enxiZ5IrwWD6ef2apGO6MvgdGhy2fpwmATmn7BpSj9lRumddLLXm7u8zSp6hnXt1hS71YDNh78LjGKGhGL4sbg8uNnpa/I6GK/83jzqGYN7+ESbg==").unwrap();
    assert_eq!(
        CipherString::from_attachment_bytes(&encrypted)
            .unwrap()
            .decrypt_type2(key.enc_key(), key.mac_key())
            .unwrap(),
        expected
    );
    for malformed in [vec![], vec![2; 49], vec![0; 65], vec![2; 66]] {
        assert!(CipherString::from_attachment_bytes(&malformed).is_err());
    }
}

struct Harness {
    _tmp: TempDir,
    upstream: MockServer,
    state: DaemonState,
    socket: PathBuf,
    server: tokio::task::JoinHandle<()>,
    _shutdown: broadcast::Sender<()>,
    encrypted: Vec<u8>,
}

impl Drop for Harness {
    fn drop(&mut self) {
        self.server.abort();
    }
}

impl Harness {
    async fn new() -> Self {
        let tmp = tempdir().unwrap();
        let socket = tmp.path().join("daemon.sock");
        let upstream = MockServer::start().await;
        let user = SymmetricKey::new([10; 64]);
        let item = SymmetricKey::new([20; 64]);
        let content = SymmetricKey::new([30; 64]);
        let state = DaemonState::new(
            StoragePaths::custom(tmp.path().join("cfg"), tmp.path().join("cache")),
            Duration::from_secs(1800),
        );
        *state.vault.write().await = Some(vault(&user, &item, &content));
        *state.symmetric_key.write().await = Some(user);
        *state.upstream_client.write().await = Some(UpstreamClient::new(&upstream.uri()).unwrap());
        *state.session.write().await = Some(SessionMetadata {
            server_url: upstream.uri(),
            email: "u@example.com".into(),
            access_token: "vault-token".into(),
            refresh_token: None,
            expires_at: None,
            kdf_params: tacet::crypto::kdf::KdfParams::pbkdf2(100000),
            protected_symmetric_key: None,
            protected_rsa_private_key: None,
            user_id: Some("user".into()),
            last_synced: None,
        });
        let listener = bind_unix_socket(&socket).await.unwrap();
        let (shutdown_tx, shutdown) = broadcast::channel(1);
        let server_state = state.clone();
        let server = tokio::spawn(async move {
            run_server(listener, server_state, shutdown).await.unwrap();
        });
        Self {
            _tmp: tmp,
            upstream,
            state,
            socket,
            server,
            _shutdown: shutdown_tx,
            encrypted: blob(&content, ORIGINAL),
        }
    }

    async fn mount(&self, bytes: Vec<u8>, delay: Duration) {
        Mock::given(method("GET"))
            .and(path(format!(
                "/api/ciphers/{ITEM_ID}/attachment/attachment-0"
            )))
            .and(bearer_token("vault-token"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(
                    serde_json::json!({"url": format!("{}/blob", self.upstream.uri())}),
                ),
            )
            .mount(&self.upstream)
            .await;
        Mock::given(method("GET"))
            .and(path("/blob"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_bytes(bytes)
                    .set_delay(delay),
            )
            .mount(&self.upstream)
            .await;
    }

    async fn cli(&self, uri: &str, extra: &[&str]) -> std::process::Output {
        tokio::process::Command::new(env!("CARGO_BIN_EXE_tacet"))
            .arg("--socket")
            .arg(&self.socket)
            .arg("read")
            .arg(uri)
            .args(extra)
            .output()
            .await
            .unwrap()
    }
}

#[tokio::test]
async fn cli_binary_output_metadata_and_text_compatibility() {
    let h = Harness::new().await;
    h.mount(h.encrypted.clone(), Duration::ZERO).await;
    for uri in [
        "tacet://personal/Server/example.exe",
        "tacet://personal/Server/files/example.exe",
    ] {
        let out = h.cli(uri, &[]).await;
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(out.stdout, ORIGINAL);
        assert!(out.stderr.is_empty());
    }
    let out = h
        .cli(
            "tacet://personal/Server/files/example.exe?encoding=base64",
            &[],
        )
        .await;
    assert!(out.status.success());
    assert_eq!(out.stdout, BASE64.encode(ORIGINAL).as_bytes());
    for (target, expected) in [
        ("password", b"field-password".as_slice()),
        ("fields/config.yml", b"".as_slice()),
    ] {
        let out = h
            .cli(&format!("tacet://personal/Server/{target}"), &[])
            .await;
        assert!(out.status.success());
        assert_eq!(out.stdout, expected);
    }
    {
        let mut vault = h.state.vault.write().await;
        vault.as_mut().unwrap().ciphers[0].notes = Some(
            SymmetricKey::new([20; 64])
                .encrypt_type2_string(" \tfirst\nsecond\r\n\n")
                .unwrap(),
        );
    }
    for (target, expected) in [
        ("notes", b" \tfirst\nsecond\r\n\n".as_slice()),
        ("notes?trim=false", b" \tfirst\nsecond\r\n\n".as_slice()),
        ("notes?trim=true", b"first\nsecond".as_slice()),
    ] {
        let out = h
            .cli(&format!("tacet://personal/Server/{target}"), &[])
            .await;
        assert!(out.status.success());
        assert_eq!(out.stdout, expected);
    }
    let client = DaemonClient::new(&h.socket);
    let listed = client.attachments(ITEM_ID).await.unwrap();
    assert_eq!(listed.attachments.len(), 6);
    assert_eq!(listed.attachments[0].name, "example.exe");
    assert_eq!(
        client.read(&listed.attachments[0].uri).await.unwrap().bytes,
        ORIGINAL
    );
    assert!(
        matches!(client.resolve(vec!["tacet://personal/Server/example.exe".into()]).await, Err(DaemonClientError::HttpStatus { status, .. }) if status.as_u16() == 400)
    );
    let requests = h.upstream.received_requests().await.unwrap();
    assert!(requests
        .iter()
        .filter(|req| req.url.path() == "/blob")
        .all(|req| !req.headers.contains_key("authorization")));
}

#[tokio::test]
async fn cli_tampered_attachment_outputs_no_plaintext() {
    let h = Harness::new().await;
    let mut tampered = h.encrypted.clone();
    tampered[49] ^= 1;
    h.mount(tampered, Duration::ZERO).await;
    let out = h.cli("tacet://personal/Server/example.exe", &[]).await;
    assert!(!out.status.success());
    assert!(out.stdout.is_empty());
    assert!(String::from_utf8_lossy(&out.stderr).contains("HMAC verification failed"));
}

#[tokio::test]
async fn lock_during_download_blocks_plaintext_and_does_not_wait_for_network() {
    let h = Harness::new().await;
    h.mount(h.encrypted.clone(), Duration::from_secs(1)).await;
    let client = DaemonClient::new(&h.socket);
    let task =
        tokio::spawn(async move { client.read("tacet://personal/Server/example.exe").await });
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if h.upstream
                .received_requests()
                .await
                .unwrap()
                .iter()
                .any(|req| req.url.path() == "/blob")
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    tokio::time::timeout(Duration::from_millis(200), h.state.lock())
        .await
        .unwrap();
    assert!(
        matches!(task.await.unwrap(), Err(DaemonClientError::HttpStatus { status, .. }) if status.as_u16() == 401)
    );
}

#[tokio::test]
async fn upstream_fallback_url_size_limit_and_no_bearer_leak() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/ciphers/item/attachment/file"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/blob"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![2, 3, 4]))
        .mount(&server)
        .await;
    let large_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let large_url = format!("http://{}/too-large", large_listener.local_addr().unwrap());
    let large_server = tokio::spawn(async move {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (mut stream, _) = large_listener.accept().await.unwrap();
        let mut request = [0; 4096];
        let received = stream.read(&mut request).await.unwrap();
        assert!(received > 0);
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 67108865\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
    });
    let client = UpstreamClient::new(&server.uri()).unwrap();
    assert_eq!(
        client
            .download_attachment(
                "secret",
                "item",
                "file",
                Some(&format!("{}/blob", server.uri()))
            )
            .await
            .unwrap(),
        vec![2, 3, 4]
    );
    assert!(matches!(
        client
            .download_attachment("secret", "item", "file", Some(&large_url))
            .await,
        Err(UpstreamError::AttachmentTooLarge)
    ));
    assert!(matches!(
        client
            .download_attachment("secret", "item", "file", Some("file:///etc/passwd"))
            .await,
        Err(UpstreamError::InvalidAttachmentUrl)
    ));
    large_server.await.unwrap();
    let requests = server.received_requests().await.unwrap();
    assert!(requests
        .iter()
        .filter(|req| req.url.path() == "/blob")
        .all(|req| !req.headers.contains_key("authorization")));
}

#[tokio::test]
async fn read_api_errors_and_expired_session_refresh() {
    use chrono::{Duration as ChronoDuration, Utc};
    use tacet::storage::vault_cache::EncryptedVaultCache;

    let h = Harness::new().await;
    let client = DaemonClient::new(&h.socket);
    for (target, expected_status) in [
        ("files/missing.exe", 404),
        ("duplicate", 409),
        ("files/example.exe?trim=false", 400),
        ("files/example.exe?json=x", 400),
    ] {
        assert!(
            matches!(client.read(&format!("tacet://personal/Server/{target}")).await,
            Err(DaemonClientError::HttpStatus { status, .. }) if status.as_u16() == expected_status)
        );
    }
    {
        let mut guard = h.state.session.write().await;
        let session = guard.as_mut().unwrap();
        session.expires_at = Some(Utc::now() - ChronoDuration::seconds(1));
        session.access_token = "expired-token".into();
        session.refresh_token = Some("refresh-token".into());
    }
    Mock::given(method("POST"))
        .and(path("/identity/connect/token"))
        .and(wiremock::matchers::body_string_contains("refresh_token=refresh-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "vault-token", "refresh_token": "new-refresh", "expires_in": 3600, "token_type": "Bearer"
        })))
        .expect(1)
        .mount(&h.upstream)
        .await;
    h.mount(h.encrypted.clone(), Duration::ZERO).await;
    assert_eq!(
        client
            .read("tacet://personal/Server/example.exe")
            .await
            .unwrap()
            .bytes,
        ORIGINAL
    );
    let saved_session = SessionMetadata::load(&h.state.storage_paths).unwrap();
    assert_eq!(saved_session.access_token, "vault-token");
    assert_eq!(saved_session.refresh_token.as_deref(), Some("new-refresh"));

    let data = h.state.vault.read().await.clone().unwrap();
    EncryptedVaultCache::new(data.clone())
        .save(&h.state.storage_paths)
        .unwrap();
    let restored = EncryptedVaultCache::load(&h.state.storage_paths).unwrap();
    assert_eq!(restored.data.ciphers[0].key, data.ciphers[0].key);
    let attachments = restored.data.ciphers[0].attachments.as_ref().unwrap();
    assert_eq!(
        attachments[0].key,
        data.ciphers[0].attachments.as_ref().unwrap()[0].key
    );
    assert_ne!(attachments[0].file_name, "example.exe");

    h.state.lock().await;
    assert!(
        matches!(client.read("tacet://personal/Server/example.exe").await,
        Err(DaemonClientError::HttpStatus { status, .. }) if status.as_u16() == 401)
    );
    assert!(matches!(client.attachments(ITEM_ID).await,
        Err(DaemonClientError::HttpStatus { status, .. }) if status.as_u16() == 401));
}

#[tokio::test]
async fn list_includes_items_with_only_attachments() {
    let h = Harness::new().await;
    {
        let mut guard = h.state.vault.write().await;
        let cipher = &mut guard.as_mut().unwrap().ciphers[0];
        cipher.login = None;
        cipher.fields = None;
        cipher.notes = None;
        cipher.cipher_type = 2;
    }
    let client = DaemonClient::new(&h.socket);
    for (scope, search) in [(None, None), (Some("personal"), Some("Server"))] {
        let listed = client.list(scope, search).await.unwrap();
        assert_eq!(listed.total, 1);
        assert_eq!(listed.items[0].id, ITEM_ID);
        assert_eq!(listed.items[0].name, "Server");
        assert_eq!(listed.items[0].cipher_type, "SecureNote");
    }
    let output = tokio::process::Command::new(env!("CARGO_BIN_EXE_tacet"))
        .arg("--socket")
        .arg(&h.socket)
        .args(["list", "--json"])
        .output()
        .await
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let listed: Vec<tacet::resolver::VaultItemSummary> =
        serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].id, ITEM_ID);
    assert_eq!(
        client.attachments(ITEM_ID).await.unwrap().attachments.len(),
        6
    );

    // Optional fields may be omitted entirely in the upstream JSON.
    let mut serialized =
        serde_json::to_value(h.state.vault.read().await.as_ref().unwrap()).unwrap();
    let cipher = serialized["ciphers"][0].as_object_mut().unwrap();
    for field in ["login", "fields", "notes"] {
        cipher.remove(field);
    }
    let restored: SyncResponse = serde_json::from_value(serialized).unwrap();
    let user = SymmetricKey::new([10; 64]);
    assert_eq!(
        VaultResolver::new(&restored, &user, None)
            .list_items(None, None)
            .unwrap()
            .len(),
        1
    );
}

#[tokio::test]
async fn list_retains_empty_unnamed_and_undecryptable_items() {
    let h = Harness::new().await;
    let item_key = SymmetricKey::new([20; 64]);
    let mut empty = h.state.vault.read().await.clone().unwrap();
    let cipher = &mut empty.ciphers[0];
    cipher.login = None;
    cipher.fields = None;
    cipher.notes = None;
    cipher.attachments = None;
    cipher.cipher_type = 2;
    cipher.name = item_key.encrypt_type2_string("Empty Item").unwrap();

    let client = DaemonClient::new(&h.socket);
    for case in [
        "named",
        "empty-name",
        "missing-name-value",
        "broken-name",
        "broken-key",
        "missing-org-key",
    ] {
        let mut data = empty.clone();
        let cipher = &mut data.ciphers[0];
        match case {
            "empty-name" => cipher.name = item_key.encrypt_type2_string("").unwrap(),
            "missing-name-value" => cipher.name.clear(),
            "broken-name" => cipher.name = "invalid-ciphertext".into(),
            "broken-key" => cipher.key = Some("invalid-key".into()),
            "missing-org-key" => {
                cipher.organization_id = Some("org-without-key".into());
                cipher.collection_ids = vec!["collection-a".into(), "collection-b".into()];
            }
            _ => {}
        }
        *h.state.vault.write().await = Some(data);
        let listed = client.list(None, None).await.unwrap();
        let expected_count = if case == "missing-org-key" { 2 } else { 1 };
        assert_eq!(listed.total, expected_count, "{case}");
        for entry in &listed.items {
            assert_eq!(entry.id, ITEM_ID, "{case}");
            assert_eq!(
                entry.name,
                if case == "named" {
                    "Empty Item"
                } else {
                    ITEM_ID
                },
                "{case}"
            );
            assert!(entry.uri_prefix.ends_with(&entry.name), "{case}");
        }
        assert_eq!(
            client.list(None, Some(ITEM_ID)).await.unwrap().total,
            expected_count,
            "{case}"
        );
        assert_eq!(
            client
                .list(None, Some("unrelated-search"))
                .await
                .unwrap()
                .total,
            0,
            "{case}"
        );
        if case == "missing-org-key" {
            assert_eq!(listed.items[0].scope, "org/org-without-key/collection-a");
            assert_eq!(listed.items[1].scope, "org/org-without-key/collection-b");
            assert_eq!(
                client
                    .list(Some("org/org-without-key/collection-a"), None)
                    .await
                    .unwrap()
                    .total,
                1
            );
            assert_eq!(client.list(Some("personal"), None).await.unwrap().total, 0);
        }
    }
    for args in [vec!["list"], vec!["list", "--json"]] {
        let output = tokio::process::Command::new(env!("CARGO_BIN_EXE_tacet"))
            .arg("--socket")
            .arg(&h.socket)
            .args(&args)
            .output()
            .await
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        if args.contains(&"--json") {
            let entries: Vec<tacet::resolver::VaultItemSummary> =
                serde_json::from_slice(&output.stdout).unwrap();
            assert_eq!(entries.len(), 2);
            assert!(entries.iter().all(|entry| entry.name == ITEM_ID));
        } else {
            let table = String::from_utf8(output.stdout).unwrap();
            assert!(table.contains(ITEM_ID));
            assert!(table.contains("Total: 2 entries (1 unique item)"));
        }
    }
}
