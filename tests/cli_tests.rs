use std::fs;
use std::time::Duration;
use tacet::cli::commands::{execute_inject, execute_list, execute_run};
use tacet::cli::masker::StreamMasker;
use tacet::crypto::symmetric_key::SymmetricKey;
use tacet::daemon::{bind_unix_socket, run_server, DaemonClient, DaemonState};
use tacet::storage::StoragePaths;
use tacet::upstream::models::{
    CipherLoginResponse, CipherResponse, CollectionResponse, ProfileOrganizationResponse,
    ProfileResponse, SyncResponse,
};
use tempfile::tempdir;
use tokio::sync::broadcast;

#[test]
fn test_stream_masker_redaction() {
    let secrets = vec![
        "super_secret_token".to_string(),
        "secret".to_string(),
        "sh".to_string(), // < 4 bytes, must NOT be masked per SPEC
    ];
    let masker = StreamMasker::new(secrets);

    // Longest matches first
    let output = masker.mask("Deploying with super_secret_token and secret for sh script");
    assert_eq!(
        output,
        "Deploying with [TACET_MASKED] and [TACET_MASKED] for sh script"
    );

    // Multiline test
    let multiline = "Line 1: secret\nLine 2: safe text\nLine 3: super_secret_token";
    let masked_ml = masker.mask(multiline);
    assert_eq!(
        masked_ml,
        "Line 1: [TACET_MASKED]\nLine 2: safe text\nLine 3: [TACET_MASKED]"
    );
}

#[tokio::test]
async fn test_cli_inject_and_fail_fast() {
    let tmp = tempdir().unwrap();
    let socket_path = tmp.path().join("inject.sock");
    let storage_paths = StoragePaths::custom(tmp.path().join("cfg"), tmp.path().join("cache"));

    // Prepare unlocked mock daemon with known secrets
    let user_key = SymmetricKey::new([33u8; 64]);
    let enc_pass = user_key
        .encrypt_type2_string("database_password_999")
        .unwrap();
    let enc_notes = user_key
        .encrypt_type2_string(r#"{"api": {"key": "secret_api_key_888"}}"#)
        .unwrap();

    let vault = SyncResponse {
        profile: Some(ProfileResponse {
            id: "u1".to_string(),
            name: None,
            email: "test@example.com".to_string(),
            key: None,
            private_key: None,
            organizations: vec![],
        }),
        folders: vec![],
        collections: vec![],
        ciphers: vec![CipherResponse {
            id: "22222222-2222-2222-2222-222222222222".to_string(),
            organization_id: None,
            folder_id: None,
            collection_ids: vec![],
            cipher_type: 1,
            name: user_key.encrypt_type2_string("AppConfig").unwrap(),
            notes: Some(enc_notes),
            favorite: None,
            login: Some(CipherLoginResponse {
                password: Some(enc_pass),
                ..Default::default()
            }),
            fields: None,
        }],
    };

    let listener = bind_unix_socket(&socket_path).await.unwrap();
    let state = DaemonState::new(storage_paths, Duration::from_secs(1800));
    *state.symmetric_key.write().await = Some(user_key);
    *state.vault.write().await = Some(vault);

    let (shutdown_tx, shutdown_rx) = broadcast::channel(1);
    let server_handle = tokio::spawn(async move {
        run_server(listener, state, shutdown_rx).await.unwrap();
    });

    let client = DaemonClient::new(&socket_path);

    // 1. Successful injection
    let template_file = tmp.path().join("config.tpl");
    let output_file = tmp.path().join("config.env");

    let tpl_content = r#"
DB_PASSWORD={{ tacet://personal/AppConfig/password }}
API_KEY={{ tacet://personal/AppConfig/notes?json=api.key }}
"#;
    fs::write(&template_file, tpl_content).unwrap();

    execute_inject(
        &client,
        Some(template_file.clone()),
        Some(output_file.clone()),
    )
    .await
    .expect("Inject failed");

    let rendered = fs::read_to_string(&output_file).unwrap();
    assert!(rendered.contains("DB_PASSWORD=database_password_999"));
    assert!(rendered.contains("API_KEY=secret_api_key_888"));

    // 2. Fail-Fast Guarantee: invalid or missing URI aborts without writing destination
    let bad_output_file = tmp.path().join("bad_config.env");
    let bad_tpl = tmp.path().join("bad_config.tpl");
    fs::write(
        &bad_tpl,
        "DB_PASS={{ tacet://personal/NonExistentItem/password }}",
    )
    .unwrap();

    let inject_err = execute_inject(&client, Some(bad_tpl), Some(bad_output_file.clone())).await;
    assert!(inject_err.is_err(), "Must abort when resolution fails");
    assert!(
        !bad_output_file.exists(),
        "Must NOT write output file on failure"
    );

    let _ = shutdown_tx.send(());
    let _ = server_handle.await;
}

#[tokio::test]
async fn test_cli_list() {
    let tmp = tempdir().unwrap();
    let socket_path = tmp.path().join("list.sock");
    let storage_paths = StoragePaths::custom(tmp.path().join("cfg"), tmp.path().join("cache"));

    let user_key = SymmetricKey::new([33u8; 64]);
    let vault = SyncResponse {
        profile: Some(ProfileResponse {
            id: "u1".to_string(),
            name: None,
            email: "test@example.com".to_string(),
            key: None,
            private_key: None,
            organizations: vec![],
        }),
        folders: vec![],
        collections: vec![],
        ciphers: vec![CipherResponse {
            id: "22222222-2222-2222-2222-222222222222".to_string(),
            organization_id: None,
            folder_id: None,
            collection_ids: vec![],
            cipher_type: 1,
            name: user_key.encrypt_type2_string("AppConfig").unwrap(),
            notes: None,
            favorite: None,
            login: None,
            fields: None,
        }],
    };

    let listener = bind_unix_socket(&socket_path).await.unwrap();
    let state = DaemonState::new(storage_paths, Duration::from_secs(1800));
    *state.symmetric_key.write().await = Some(user_key);
    *state.vault.write().await = Some(vault);

    let (shutdown_tx, shutdown_rx) = broadcast::channel(1);
    let server_handle = tokio::spawn(async move {
        run_server(listener, state, shutdown_rx).await.unwrap();
    });

    let client = DaemonClient::new(&socket_path);

    // List execution in table and json mode
    assert!(execute_list(&client, None, None, false).await.is_ok());
    assert!(execute_list(&client, None, None, true).await.is_ok());
    assert!(
        execute_list(&client, Some("personal".into()), Some("App".into()), false)
            .await
            .is_ok()
    );

    let _ = shutdown_tx.send(());
    let _ = server_handle.await;
}

#[tokio::test]
async fn test_cli_list_multiple_collections() {
    let tmp = tempdir().unwrap();
    let socket_path = tmp.path().join("list.sock");
    let storage_paths = StoragePaths::custom(tmp.path().join("cfg"), tmp.path().join("cache"));
    let user_key = SymmetricKey::new([33u8; 64]);
    let org_key = SymmetricKey::new([44u8; 64]);
    let vault = SyncResponse {
        profile: Some(ProfileResponse {
            id: "u1".to_string(),
            name: None,
            email: "test@example.com".to_string(),
            key: None,
            private_key: None,
            organizations: vec![ProfileOrganizationResponse {
                id: "org-1".to_string(),
                name: "Default".to_string(),
                key: Some(user_key.encrypt_type2(org_key.as_bytes()).unwrap()),
            }],
        }),
        folders: vec![],
        collections: ["Network/Umbilical/Infra", "Network/Koshi/Infra"]
            .into_iter()
            .enumerate()
            .map(|(index, name)| CollectionResponse {
                id: format!("col-{index}"),
                organization_id: "org-1".to_string(),
                name: org_key.encrypt_type2_string(name).unwrap(),
            })
            .collect(),
        ciphers: vec![CipherResponse {
            id: "22222222-2222-2222-2222-222222222222".to_string(),
            organization_id: Some("org-1".to_string()),
            folder_id: None,
            collection_ids: vec!["col-0".to_string(), "col-1".to_string()],
            cipher_type: 1,
            name: org_key.encrypt_type2_string("infra.domains").unwrap(),
            notes: None,
            favorite: None,
            login: None,
            fields: None,
        }],
    };

    let listener = bind_unix_socket(&socket_path).await.unwrap();
    let state = DaemonState::new(storage_paths, Duration::from_secs(1800));
    *state.symmetric_key.write().await = Some(user_key);
    *state.vault.write().await = Some(vault);
    let (shutdown_tx, shutdown_rx) = broadcast::channel(1);
    let server_handle = tokio::spawn(async move {
        run_server(listener, state, shutdown_rx).await.unwrap();
    });

    let client = DaemonClient::new(&socket_path);
    let response = client.list(None, None).await.unwrap();
    assert_eq!(response.total, 2);
    assert_eq!(response.items[0].id, response.items[1].id);
    for (args, expected_footer, expected_count) in [
        (vec![], "Total: 2 entries (1 unique item)", 2),
        (
            vec!["org/Default/Network/Koshi/Infra"],
            "Total: 1 entry (1 unique item)",
            1,
        ),
    ] {
        let output = tokio::process::Command::new(env!("CARGO_BIN_EXE_tacet"))
            .arg("--socket")
            .arg(&socket_path)
            .arg("list")
            .args(&args)
            .output()
            .await
            .unwrap();
        assert!(output.status.success(), "{:?}", output.stderr);
        let table = String::from_utf8(output.stdout).unwrap();
        assert!(table.contains(expected_footer), "{table}");
        assert!(table.contains("tacet://org/Default/Network/Koshi/Infra/infra.domains"));
        assert_eq!(
            table.contains("Network/Umbilical/Infra"),
            expected_count == 2
        );

        let output = tokio::process::Command::new(env!("CARGO_BIN_EXE_tacet"))
            .arg("--socket")
            .arg(&socket_path)
            .args(["list", "--json"])
            .args(&args)
            .output()
            .await
            .unwrap();
        assert!(output.status.success(), "{:?}", output.stderr);
        let entries: Vec<tacet::resolver::VaultItemSummary> =
            serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(entries.len(), expected_count);
        assert_eq!(entries, response.items[..expected_count]);
    }

    let _ = shutdown_tx.send(());
    server_handle.await.unwrap();
}

#[tokio::test]
async fn test_cli_run_environment_injection_and_masking() {
    let tmp = tempdir().unwrap();
    let socket_path = tmp.path().join("run.sock");
    let storage_paths = StoragePaths::custom(tmp.path().join("cfg"), tmp.path().join("cache"));

    let user_key = SymmetricKey::new([55u8; 64]);
    let enc_pass = user_key
        .encrypt_type2_string("super_secret_db_pass")
        .unwrap();

    let vault = SyncResponse {
        profile: None,
        folders: vec![],
        collections: vec![],
        ciphers: vec![CipherResponse {
            id: "33333333-3333-3333-3333-333333333333".to_string(),
            organization_id: None,
            folder_id: None,
            collection_ids: vec![],
            cipher_type: 1,
            name: user_key.encrypt_type2_string("PostgresServer").unwrap(),
            notes: None,
            favorite: None,
            login: Some(CipherLoginResponse {
                password: Some(enc_pass),
                ..Default::default()
            }),
            fields: None,
        }],
    };

    let listener = bind_unix_socket(&socket_path).await.unwrap();
    let state = DaemonState::new(storage_paths, Duration::from_secs(1800));
    *state.symmetric_key.write().await = Some(user_key);
    *state.vault.write().await = Some(vault);

    let (shutdown_tx, shutdown_rx) = broadcast::channel(1);
    let server_handle = tokio::spawn(async move {
        run_server(listener, state, shutdown_rx).await.unwrap();
    });

    let client = DaemonClient::new(&socket_path);

    // 1. Create .env file with tacet:// placeholder
    let env_file = tmp.path().join(".env.test");
    fs::write(
        &env_file,
        "DB_PASS=tacet://personal/PostgresServer/password\nPLAIN_VAR=hello\n",
    )
    .unwrap();

    // 2. Execute command injecting the env var
    let cmd = vec![
        "sh".to_string(),
        "-c".to_string(),
        "if [ \"$DB_PASS\" = \"super_secret_db_pass\" ] && [ \"$PLAIN_VAR\" = \"hello\" ]; then exit 0; else exit 2; fi".to_string(),
    ];

    let exit_code = execute_run(&client, Some(env_file.clone()), false, cmd)
        .await
        .expect("Run failed");

    assert_eq!(
        exit_code, 0,
        "Subprocess should receive resolved environment variable"
    );

    // 3. Fail-Fast Guarantee: invalid URI in env file aborts BEFORE running command
    let bad_env_file = tmp.path().join(".env.bad");
    fs::write(
        &bad_env_file,
        "DB_PASS=tacet://personal/MissingItem/password\n",
    )
    .unwrap();

    let bad_cmd = vec![
        "sh".to_string(),
        "-c".to_string(),
        "touch /tmp/should_never_run".to_string(),
    ];

    let bad_run = execute_run(&client, Some(bad_env_file), false, bad_cmd).await;
    assert!(bad_run.is_err(), "Must abort before executing command");

    let _ = shutdown_tx.send(());
    let _ = server_handle.await;
}
