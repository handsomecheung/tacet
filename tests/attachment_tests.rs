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
const TEXT_ATTACHMENT: &str = " \tfirst secret line\r\nsecond secret line 日本語\n\n ";

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
        TacetUri::parse("tacet://personal/Server/files/config.yml")
            .unwrap()
            .scope,
        Scope::Personal { folder: None }
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
            let attachments = resolver.list_attachments(ITEM_ID).unwrap();
            let discovered_uri = TacetUri::parse(&attachments[0].uri).unwrap();
            assert_eq!(discovered_uri.item, ITEM_ID);
            assert_eq!(
                discovered_uri.scope,
                if organization {
                    Scope::Organization {
                        org_name: "org-id".into(),
                        collection: None,
                    }
                } else {
                    Scope::Personal { folder: None }
                }
            );
            let ReadTarget::Attachment(selected) = resolver.select_read(&discovered_uri).unwrap()
            else {
                panic!("Expected attachment")
            };
            assert_eq!(
                resolver
                    .decrypt_attachment(&selected, &blob(content_key, ORIGINAL), &discovered_uri)
                    .unwrap(),
                ORIGINAL
            );
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
            api_client_id: None,
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
async fn wildcard_references_fail_before_output_or_execution() {
    let h = Harness::new().await;
    let client = DaemonClient::new(&h.socket);
    for uri in [
        "tacet://*/Server/password",
        "tacet://%2A/Server/files/example.exe",
    ] {
        assert!(matches!(client.read(uri).await,
            Err(DaemonClientError::HttpStatus { status, message, .. })
                if status == 400 && message.contains("Wildcard scope")
        ));
        assert!(matches!(client.resolve(vec![uri.to_string()]).await,
            Err(DaemonClientError::HttpStatus { status, message, .. })
                if status == 400 && message.contains("Wildcard scope")
        ));
        let output = h.cli(uri, &[]).await;
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert!(String::from_utf8_lossy(&output.stderr).contains("Wildcard scope"));
    }
    assert!(matches!(
        client.list(Some("*"), None).await,
        Err(DaemonClientError::HttpStatus { status, .. }) if status == 400
    ));
    assert_eq!(client.list(None, None).await.unwrap().total, 1);

    let template = h._tmp.path().join("template");
    let destination = h._tmp.path().join("rendered");
    let text = "{{ tacet://personal/Server/password }} {{ tacet://*/Server/password }}";
    std::fs::write(&template, text).unwrap();
    std::fs::write(&destination, "original content").unwrap();
    let output = h
        .cli_with_env(
            &[
                "inject",
                "-i",
                template.to_str().unwrap(),
                "-o",
                destination.to_str().unwrap(),
            ],
            &[],
        )
        .await;
    assert!(!output.status.success());
    assert_eq!(
        std::fs::read_to_string(&destination).unwrap(),
        "original content"
    );
    let output = h
        .cli_with_env(
            &["inject", "-i", template.to_str().unwrap(), "--in-place"],
            &[],
        )
        .await;
    assert!(!output.status.success());
    assert_eq!(std::fs::read_to_string(&template).unwrap(), text);

    let marker = h._tmp.path().join("child-ran");
    let output = h
        .cli_with_env(
            &["run", "--", "touch", marker.to_str().unwrap()],
            &[("TACET_WILDCARD_TEST", "tacet://*/Server/password")],
        )
        .await;
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(!marker.exists());
    assert!(h.upstream.received_requests().await.unwrap().is_empty());
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
    assert!(matches!(
        client.resolve(vec!["tacet://personal/Server/example.exe".into()]).await,
        Err(DaemonClientError::HttpStatus { status, message, .. })
            if status.as_u16() == 400 && message.contains("not valid UTF-8")
    ));
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
async fn batch_resolves_fields_and_explicit_or_implicit_text_attachments() {
    let h = Harness::new().await;
    h.mount(
        blob(&SymmetricKey::new([30; 64]), TEXT_ATTACHMENT.as_bytes()),
        Duration::ZERO,
    )
    .await;
    let client = DaemonClient::new(&h.socket);
    let cases = [
        ("example.exe", TEXT_ATTACHMENT.to_string()),
        ("files/example.exe", TEXT_ATTACHMENT.to_string()),
        ("files/attachment-0", TEXT_ATTACHMENT.to_string()),
        ("password", "field-password".into()),
        ("config.yml", "".into()),
        (
            "files/example.exe?encoding=base64",
            BASE64.encode(TEXT_ATTACHMENT),
        ),
        (
            "example.exe?encoding=hex",
            TEXT_ATTACHMENT
                .as_bytes()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect(),
        ),
    ];
    let uris: Vec<_> = cases
        .iter()
        .map(|(target, _)| format!("tacet://personal/Server/{target}"))
        .collect();
    let response = client.resolve(uris.clone()).await.unwrap();
    for (uri, (_, expected)) in uris.iter().zip(cases) {
        assert_eq!(response.secrets[uri], expected, "{uri}");
    }
}

#[tokio::test]
async fn cli_injects_attachments_to_stdout_directories_and_in_place() {
    let h = Harness::new().await;
    h.mount(
        blob(&SymmetricKey::new([30; 64]), TEXT_ATTACHMENT.as_bytes()),
        Duration::ZERO,
    )
    .await;
    let source = h._tmp.path().join("templates");
    std::fs::create_dir(&source).unwrap();
    let template = source.join("config");
    let template_text = "prefix:{{ tacet://personal/Server/example.exe }}:suffix";
    let expected = format!("prefix:{TEXT_ATTACHMENT}:suffix");
    std::fs::write(&template, template_text).unwrap();
    let input = template.to_str().unwrap();
    let output = h.cli_with_env(&["inject", "-i", input], &[]).await;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, expected.as_bytes());

    let destination = h._tmp.path().join("rendered");
    let output = h
        .cli_with_env(
            &[
                "inject",
                "--in-dir",
                source.to_str().unwrap(),
                "--out-dir",
                destination.to_str().unwrap(),
            ],
            &[],
        )
        .await;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        std::fs::read(destination.join("config")).unwrap(),
        expected.as_bytes()
    );

    std::fs::write(&template, "{{ tacet://personal/Server/files/example.exe }}").unwrap();
    let output = h
        .cli_with_env(&["inject", "-i", input, "--in-place"], &[])
        .await;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        std::fs::read(&template).unwrap(),
        TEXT_ATTACHMENT.as_bytes()
    );
}

#[tokio::test]
async fn cli_run_preserves_attachment_whitespace_and_masks_multiline_output() {
    let h = Harness::new().await;
    h.mount(
        blob(&SymmetricKey::new([30; 64]), TEXT_ATTACHMENT.as_bytes()),
        Duration::ZERO,
    )
    .await;
    for reference in [
        "tacet://personal/Server/example.exe",
        "tacet://personal/Server/files/example.exe",
        "{{ tacet://personal/Server/files/example.exe }}",
    ] {
        let output = h
            .cli_with_env(
                &[
                    "run",
                    "--no-mask",
                    "--",
                    "sh",
                    "-c",
                    "printf '%s' \"$TACET_TEST_ATTACHMENT\"",
                ],
                &[("TACET_TEST_ATTACHMENT", reference)],
            )
            .await;
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(output.stdout, TEXT_ATTACHMENT.as_bytes());
    }
    let output = h.cli_with_env(
        &["run", "--", "sh", "-c", "printf '%s' \"$TACET_TEST_ATTACHMENT\"; printf '%s' \"$TACET_TEST_ATTACHMENT\" >&2"],
        &[("TACET_TEST_ATTACHMENT", "tacet://personal/Server/example.exe")],
    ).await;
    assert!(output.status.success());
    let expected = b"[TACET_MASKED]\n[TACET_MASKED]\n\n \n";
    assert_eq!(output.stdout, expected);
    assert_eq!(output.stderr, expected);
}

#[tokio::test]
async fn cli_attachment_failures_abort_before_writes_or_child_execution() {
    for failure in ["utf8", "nul", "tampered", "missing", "download"] {
        let h = Harness::new().await;
        let mut bytes = match failure {
            "nul" => blob(&SymmetricKey::new([30; 64]), b"secret\0value"),
            _ => h.encrypted.clone(),
        };
        if failure == "tampered" {
            bytes[49] ^= 1;
        }
        if failure == "download" {
            Mock::given(method("GET"))
                .and(path(format!(
                    "/api/ciphers/{ITEM_ID}/attachment/attachment-0"
                )))
                .respond_with(ResponseTemplate::new(404))
                .expect(2)
                .mount(&h.upstream)
                .await;
        } else {
            h.mount(bytes, Duration::ZERO).await;
        }
        let uri = if failure == "missing" {
            "tacet://personal/Server/files/missing"
        } else {
            "tacet://personal/Server/example.exe"
        };
        let expected_error = match failure {
            "nul" => "NUL byte",
            "tampered" => "HMAC verification failed",
            "missing" => "404 Not Found",
            "download" => "Could not obtain attachment download URL",
            _ => "not valid UTF-8",
        };
        let marker = h._tmp.path().join("child-ran");
        let output = h
            .cli_with_env(
                &[
                    "run",
                    "--",
                    "sh",
                    "-c",
                    "touch \"$1\"",
                    "sh",
                    marker.to_str().unwrap(),
                ],
                &[("TACET_TEST_ATTACHMENT", uri)],
            )
            .await;
        assert!(!output.status.success(), "{failure}");
        assert!(output.stdout.is_empty());
        assert!(
            String::from_utf8_lossy(&output.stderr).contains(expected_error),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!String::from_utf8_lossy(&output.stderr).contains("secret\0value"));
        assert!(!marker.exists());

        let source = h._tmp.path().join("templates");
        std::fs::create_dir(&source).unwrap();
        let template = source.join("attachment");
        let contents = format!("{{{{ {uri} }}}}");
        std::fs::write(&template, &contents).unwrap();
        std::fs::write(
            source.join("field"),
            "{{ tacet://personal/Server/password }}",
        )
        .unwrap();
        let output = h
            .cli_with_env(
                &["inject", "--in-dir", source.to_str().unwrap(), "--in-place"],
                &[],
            )
            .await;
        if failure == "nul" {
            // NUL is valid UTF-8 and is supported in rendered files, but not environments.
            assert!(output.status.success());
            assert_eq!(std::fs::read(&template).unwrap(), b"secret\0value");
        } else {
            assert!(!output.status.success(), "{failure}");
            assert!(output.stdout.is_empty());
            assert!(String::from_utf8_lossy(&output.stderr).contains(expected_error));
            assert_eq!(std::fs::read_to_string(&template).unwrap(), contents);
            assert_eq!(
                std::fs::read_to_string(source.join("field")).unwrap(),
                "{{ tacet://personal/Server/password }}"
            );
        }
    }
}

#[tokio::test]
async fn cli_inject_and_run_encode_binary_attachments_and_reauthenticate() {
    for operation in ["inject", "run"] {
        let h = Harness::new().await;
        h.expire_api_session().await;
        h.mount_api_reauthentication(200).await;
        h.mount(h.encrypted.clone(), Duration::ZERO).await;
        let uri = "tacet://personal/Server/example.exe?encoding=base64";
        let output = if operation == "inject" {
            let template = h._tmp.path().join("template");
            std::fs::write(&template, format!("{{{{ {uri} }}}}")).unwrap();
            h.cli_with_env(&["inject", "-i", template.to_str().unwrap()], CI_API_ENV)
                .await
        } else {
            let mut env = CI_API_ENV.to_vec();
            env.push(("TACET_TEST_ATTACHMENT", uri));
            h.cli_with_env(
                &[
                    "run",
                    "--no-mask",
                    "--",
                    "sh",
                    "-c",
                    "printf '%s' \"$TACET_TEST_ATTACHMENT\"",
                ],
                &env,
            )
            .await
        };
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(output.stdout, BASE64.encode(ORIGINAL).as_bytes());
        assert!(output.stderr.is_empty());
        assert!(h.state.is_unlocked().await);
    }
}

#[tokio::test]
async fn lock_during_download_blocks_plaintext_and_does_not_wait_for_network() {
    for batch in [false, true] {
        let h = Harness::new().await;
        h.mount(h.encrypted.clone(), Duration::from_secs(1)).await;
        let client = DaemonClient::new(&h.socket);
        let task = tokio::spawn(async move {
            if batch {
                client
                    .resolve(vec!["tacet://personal/Server/example.exe".into()])
                    .await
                    .map(|_| ())
            } else {
                client
                    .read("tacet://personal/Server/example.exe")
                    .await
                    .map(|_| ())
            }
        });
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
        assert!(
            matches!(client.resolve(vec![format!("tacet://personal/Server/{target}")]).await,
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

impl Harness {
    async fn expire_api_session(&self) {
        let mut guard = self.state.session.write().await;
        let session = guard.as_mut().unwrap();
        session.api_client_id = Some("user.api-user".into());
        session.access_token = "old-token".into();
        session.expires_at = Some(chrono::Utc::now() - chrono::Duration::seconds(1));
        session.save(&self.state.storage_paths).unwrap();
    }

    async fn mount_api_reauthentication(&self, status: u16) {
        Mock::given(method("POST"))
            .and(path("/identity/connect/token"))
            .and(wiremock::matchers::body_string_contains(
                "grant_type=client_credentials",
            ))
            .and(wiremock::matchers::body_string_contains(
                "client_id=user.api-user",
            ))
            .and(wiremock::matchers::body_string_contains(
                "client_secret=ci-api-secret",
            ))
            .respond_with(
                ResponseTemplate::new(status).set_body_json(serde_json::json!({
                    "access_token": "vault-token", "expires_in": 7200, "token_type": "Bearer"
                })),
            )
            .expect(1)
            .mount(&self.upstream)
            .await;
    }

    async fn cli_with_env(&self, args: &[&str], env: &[(&str, &str)]) -> std::process::Output {
        let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_tacet"));
        command.arg("--socket").arg(&self.socket).args(args);
        for name in [
            "TACET_CLIENT_ID",
            "TACET_CLIENT_SECRET",
            "TACET_PASSWORD",
            "BW_CLIENTID",
            "BW_CLIENTSECRET",
            "BW_PASSWORD",
            "TACET_SERVER",
            "TACET_EMAIL",
        ] {
            command.env_remove(name);
        }
        command
            .envs(env.iter().copied())
            .stdin(std::process::Stdio::null());
        tokio::time::timeout(Duration::from_secs(5), command.output())
            .await
            .unwrap()
            .unwrap()
    }
}

const CI_API_ENV: &[(&str, &str)] = &[
    ("TACET_CLIENT_ID", "api-user"),
    ("TACET_CLIENT_SECRET", "ci-api-secret"),
];

#[tokio::test]
async fn cli_api_reauthentication_uses_current_env_and_preserves_unlocked_vault() {
    for env in [
        vec![
            ("TACET_CLIENT_ID", " 'api-user' "),
            ("TACET_CLIENT_SECRET", "ci-api-secret"),
            ("BW_CLIENTID", "wrong-user"),
            ("BW_CLIENTSECRET", "wrong-secret"),
            ("TACET_SERVER", "http://unused.invalid"),
        ],
        vec![
            ("BW_CLIENTID", "user.api-user"),
            ("BW_CLIENTSECRET", "ci-api-secret"),
        ],
    ] {
        let h = Harness::new().await;
        h.expire_api_session().await;
        h.mount_api_reauthentication(200).await;
        h.mount(h.encrypted.clone(), Duration::ZERO).await;

        let output = h
            .cli_with_env(&["read", "tacet://personal/Server/example.exe"], &env)
            .await;
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(output.stdout, ORIGINAL);
        assert!(output.stderr.is_empty());
        assert!(h.state.is_unlocked().await);
        let session = SessionMetadata::load(&h.state.storage_paths).unwrap();
        assert_eq!(session.access_token, "vault-token");
        assert_eq!(session.api_client_id.as_deref(), Some("user.api-user"));
        assert!(session.expires_at.unwrap() > chrono::Utc::now());
        let saved = std::fs::read_to_string(h.state.storage_paths.session_file()).unwrap();
        assert!(!saved.contains("ci-api-secret") && !saved.contains("client_secret"));
        let requests = h.upstream.received_requests().await.unwrap();
        assert_eq!(requests.len(), 3);
        assert!(requests.iter().all(|r| r.url.path() != "/api/sync"));
    }
}

#[tokio::test]
async fn cli_sync_reauthenticates_for_expiry_and_upstream_401() {
    for expired in [true, false] {
        let h = Harness::new().await;
        h.expire_api_session().await;
        if !expired {
            h.state.session.write().await.as_mut().unwrap().expires_at = None;
        }
        h.mount_api_reauthentication(200).await;
        Mock::given(method("GET"))
            .and(path("/api/sync"))
            .and(bearer_token("old-token"))
            .respond_with(ResponseTemplate::new(401))
            .expect(if expired { 0 } else { 1 })
            .mount(&h.upstream)
            .await;
        let vault = h.state.vault.read().await.clone().unwrap();
        Mock::given(method("GET"))
            .and(path("/api/sync"))
            .and(bearer_token("vault-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&vault))
            .expect(1)
            .mount(&h.upstream)
            .await;

        let output = h.cli_with_env(&["sync"], CI_API_ENV).await;
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            String::from_utf8(output.stdout).unwrap(),
            "✓ Vault synchronized successfully (1 items).\n"
        );
        assert!(output.stderr.is_empty());
        assert!(h.state.is_unlocked().await);
        let saved = SessionMetadata::load(&h.state.storage_paths).unwrap();
        assert_eq!(saved.access_token, "vault-token");
        assert!(saved.last_synced.is_some());
    }
}

#[tokio::test]
async fn cli_attachment_reauthenticates_when_server_rejects_unexpired_token() {
    let h = Harness::new().await;
    h.expire_api_session().await;
    h.state.session.write().await.as_mut().unwrap().expires_at = None;
    h.mount_api_reauthentication(200).await;
    Mock::given(method("GET"))
        .and(path(format!(
            "/api/ciphers/{ITEM_ID}/attachment/attachment-0"
        )))
        .and(bearer_token("old-token"))
        .respond_with(ResponseTemplate::new(401))
        .expect(1)
        .mount(&h.upstream)
        .await;
    h.mount(h.encrypted.clone(), Duration::ZERO).await;

    let output = h
        .cli_with_env(&["read", "tacet://personal/Server/example.exe"], CI_API_ENV)
        .await;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, ORIGINAL);
    assert!(output.stderr.is_empty());
}

#[tokio::test]
async fn cli_does_not_reauthenticate_without_matching_api_session_and_credentials() {
    for env in [
        vec![],
        vec![("TACET_CLIENT_ID", "api-user")],
        vec![("TACET_CLIENT_SECRET", "ci-api-secret")],
        vec![
            ("TACET_CLIENT_ID", "api-user"),
            ("TACET_CLIENT_SECRET", "  "),
        ],
        vec![
            ("TACET_CLIENT_ID", "other-user"),
            ("TACET_CLIENT_SECRET", "ci-api-secret"),
        ],
        CI_API_ENV.to_vec(),
    ] {
        let h = Harness::new().await;
        h.expire_api_session().await;
        if env == CI_API_ENV {
            h.state
                .session
                .write()
                .await
                .as_mut()
                .unwrap()
                .api_client_id = None;
        }
        let output = h
            .cli_with_env(&["read", "tacet://personal/Server/example.exe"], &env)
            .await;
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert!(String::from_utf8_lossy(&output.stderr).contains("Session expired"));
        assert!(h.upstream.received_requests().await.unwrap().is_empty());
    }
}

#[tokio::test]
async fn cli_cached_fields_lookup_errors_and_locked_vault_do_not_reauthenticate() {
    let h = Harness::new().await;
    h.expire_api_session().await;
    let output = h
        .cli_with_env(&["read", "tacet://personal/Server/password"], CI_API_ENV)
        .await;
    assert!(output.status.success());
    assert_eq!(output.stdout, b"field-password");
    let output = h
        .cli_with_env(
            &["read", "tacet://personal/Server/files/missing"],
            CI_API_ENV,
        )
        .await;
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("404 Not Found"));
    h.state.lock().await;
    let output = h
        .cli_with_env(&["read", "tacet://personal/Server/password"], CI_API_ENV)
        .await;
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("tacet unlock"));
    assert!(h.upstream.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn cli_reauthentication_failures_are_bounded_and_do_not_leak_credentials() {
    for token_status in [200, 401, 503] {
        let h = Harness::new().await;
        h.expire_api_session().await;
        h.mount_api_reauthentication(token_status).await;
        Mock::given(method("GET"))
            .and(path(format!(
                "/api/ciphers/{ITEM_ID}/attachment/attachment-0"
            )))
            .and(bearer_token("vault-token"))
            .respond_with(ResponseTemplate::new(401))
            .expect(if token_status == 200 { 1 } else { 0 })
            .mount(&h.upstream)
            .await;
        let output = h
            .cli_with_env(&["read", "tacet://personal/Server/example.exe"], CI_API_ENV)
            .await;
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        let error = String::from_utf8(output.stderr).unwrap();
        assert!(!error.contains("ci-api-secret"));
        assert!(
            error.contains(if token_status == 503 {
                "502 Bad Gateway"
            } else {
                "401 Unauthorized"
            }),
            "{error}"
        );
        assert!(h.state.is_unlocked().await);
        if token_status != 200 {
            let saved = SessionMetadata::load(&h.state.storage_paths).unwrap();
            assert_eq!(saved.access_token, "old-token");
        }
    }
}

#[tokio::test]
async fn cli_blob_401_does_not_reauthenticate_vault_session() {
    let h = Harness::new().await;
    h.expire_api_session().await;
    h.state.session.write().await.as_mut().unwrap().expires_at = None;
    Mock::given(method("GET"))
        .and(path(format!(
            "/api/ciphers/{ITEM_ID}/attachment/attachment-0"
        )))
        .and(bearer_token("old-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "url": format!("{}/blob", h.upstream.uri())
        })))
        .expect(1)
        .mount(&h.upstream)
        .await;
    Mock::given(method("GET"))
        .and(path("/blob"))
        .respond_with(ResponseTemplate::new(401))
        .expect(1)
        .mount(&h.upstream)
        .await;
    let output = h
        .cli_with_env(&["read", "tacet://personal/Server/example.exe"], CI_API_ENV)
        .await;
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("502 Bad Gateway"));
    assert_eq!(h.upstream.received_requests().await.unwrap().len(), 2);
}

#[tokio::test]
async fn cli_api_reauthentication_distinguishes_invalid_refresh_from_server_outage() {
    for refresh_status in [400, 503] {
        let h = Harness::new().await;
        h.expire_api_session().await;
        h.state
            .session
            .write()
            .await
            .as_mut()
            .unwrap()
            .refresh_token = Some("old-refresh".into());
        Mock::given(method("POST"))
            .and(path("/identity/connect/token"))
            .and(wiremock::matchers::body_string_contains(
                "grant_type=refresh_token",
            ))
            .respond_with(ResponseTemplate::new(refresh_status))
            .expect(1)
            .mount(&h.upstream)
            .await;
        if refresh_status == 400 {
            h.mount_api_reauthentication(200).await;
            h.mount(h.encrypted.clone(), Duration::ZERO).await;
        }
        let output = h
            .cli_with_env(&["read", "tacet://personal/Server/example.exe"], CI_API_ENV)
            .await;
        if refresh_status == 400 {
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert_eq!(output.stdout, ORIGINAL);
        } else {
            assert!(!output.status.success());
            assert!(output.stdout.is_empty());
            assert!(String::from_utf8_lossy(&output.stderr).contains("502 Bad Gateway"));
            assert_eq!(h.upstream.received_requests().await.unwrap().len(), 1);
        }
    }
}

#[tokio::test]
async fn reauthentication_endpoint_rejects_password_sessions_and_account_switches() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    for api_client_id in [None, Some("user.other-user".to_string())] {
        let h = Harness::new().await;
        h.expire_api_session().await;
        h.state
            .session
            .write()
            .await
            .as_mut()
            .unwrap()
            .api_client_id = api_client_id;
        let body = serde_json::json!({
            "client_id": "user.api-user", "client_secret": "ci-api-secret"
        })
        .to_string();
        let request = format!("POST /v1/reauthenticate HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
        let mut stream = tokio::net::UnixStream::connect(&h.socket).await.unwrap();
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.unwrap();
        assert!(String::from_utf8(response)
            .unwrap()
            .starts_with("HTTP/1.1 400 Bad Request"));
        assert!(h.upstream.received_requests().await.unwrap().is_empty());
        assert_eq!(
            h.state.session.read().await.as_ref().unwrap().access_token,
            "old-token"
        );
    }
}

#[tokio::test]
async fn cli_api_reauthentication_does_not_unlock_a_locked_vault() {
    let h = Harness::new().await;
    h.expire_api_session().await;
    h.state.lock().await;
    h.mount_api_reauthentication(200).await;
    let vault = h.state.vault.read().await.clone().unwrap();
    Mock::given(method("GET"))
        .and(path("/api/sync"))
        .and(bearer_token("vault-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&vault))
        .expect(1)
        .mount(&h.upstream)
        .await;
    let output = h.cli_with_env(&["sync"], CI_API_ENV).await;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!h.state.is_unlocked().await);
}
