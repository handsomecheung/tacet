use clap::Parser;
use std::fs;
use std::time::Duration;
use tacet::cli::commands::{
    execute_inject, execute_inject_dir, execute_inject_file_in_place, execute_list, execute_run,
};
use tacet::cli::masker::StreamMasker;
use tacet::cli::{Cli, Commands};
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
fn test_inject_arguments() {
    let cli = Cli::try_parse_from(["tacet", "inject", "--in-dir", "configs", "--in-place"])
        .expect("in-place mode must not require --out-dir");
    assert!(matches!(
        cli.command,
        Commands::Inject {
            in_dir: Some(_),
            out_dir: None,
            in_place: true,
            force: false,
            copy_all: false,
            ..
        }
    ));

    let cli = Cli::try_parse_from(["tacet", "inject", "-i", "config.env", "--in-place"])
        .expect("file in-place mode must not require --out-dir");
    assert!(matches!(
        cli.command,
        Commands::Inject {
            input: Some(_),
            output: None,
            in_dir: None,
            out_dir: None,
            in_place: true,
            ..
        }
    ));

    for args in [
        vec!["tacet", "inject"],
        vec!["tacet", "inject", "--in", "template", "--in-place"],
        vec!["tacet", "inject", "-i", "template", "-o", "output"],
        vec!["tacet", "inject", "--in-dir", "configs", "--out-dir", "out"],
        vec![
            "tacet",
            "inject",
            "--in-dir",
            "configs",
            "--out-dir",
            "out",
            "--force",
            "--copy-all",
        ],
    ] {
        assert!(Cli::try_parse_from(&args).is_ok(), "{args:?}");
    }

    for args in [
        vec!["tacet", "inject", "--in-dir", "configs"],
        vec!["tacet", "inject", "--out-dir", "out"],
        vec!["tacet", "inject", "--in-place"],
        vec!["tacet", "inject", "-o", "output", "--in-place"],
        vec![
            "tacet",
            "inject",
            "-i",
            "template",
            "--in-place",
            "-o",
            "output",
        ],
        vec![
            "tacet",
            "inject",
            "-i",
            "template",
            "--in-place",
            "--out-dir",
            "out",
        ],
        vec!["tacet", "inject", "-i", "template", "--in-place", "--force"],
        vec![
            "tacet",
            "inject",
            "-i",
            "template",
            "--in-place",
            "--copy-all",
        ],
        vec![
            "tacet",
            "inject",
            "--in-dir",
            "configs",
            "--in-place",
            "--out-dir",
            "out",
        ],
        vec![
            "tacet",
            "inject",
            "--in-dir",
            "configs",
            "--in-place",
            "--force",
        ],
        vec![
            "tacet",
            "inject",
            "--in-dir",
            "configs",
            "--in-place",
            "--copy-all",
        ],
        vec![
            "tacet",
            "inject",
            "--in-dir",
            "configs",
            "--in-place",
            "-i",
            "template",
        ],
        vec![
            "tacet",
            "inject",
            "--in-dir",
            "configs",
            "--in-place",
            "-o",
            "output",
        ],
    ] {
        assert!(Cli::try_parse_from(&args).is_err(), "{args:?}");
    }
}

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
            deleted_date: None,
            key: None,
            attachments: None,
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

    // 3. Directory mode
    {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let src = tmp.path().join("src_dir");
        fs::create_dir_all(src.join("a/b")).unwrap();
        fs::write(
            src.join("a/b/app.env"),
            "P={{ tacet://personal/AppConfig/password }}",
        )
        .unwrap();
        fs::write(src.join("plain.txt"), "no secrets").unwrap();
        fs::write(src.join("bin.dat"), [0xff, 0xfe, 0x00]).unwrap();
        symlink(src.join("plain.txt"), src.join("link.txt")).unwrap();

        let dst = tmp.path().join("dst_dir");
        execute_inject_dir(&client, src.clone(), dst.clone(), false, false)
            .await
            .expect("dir inject failed");
        assert_eq!(
            fs::read_to_string(dst.join("a/b/app.env")).unwrap(),
            "P=database_password_999"
        );
        assert!(!dst.join("plain.txt").exists());
        assert!(!dst.join("bin.dat").exists());
        let mode = fs::metadata(dst.join("a/b/app.env"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);

        // Existing output without --force fails and writes nothing new
        let err = execute_inject_dir(&client, src.clone(), dst.clone(), false, true).await;
        assert!(err.is_err());
        assert!(!dst.join("plain.txt").exists());

        // --force with --copy-all overwrites and copies everything but symlinks
        execute_inject_dir(&client, src.clone(), dst.clone(), true, true)
            .await
            .expect("forced dir inject failed");
        assert_eq!(
            fs::read_to_string(dst.join("plain.txt")).unwrap(),
            "no secrets"
        );
        assert_eq!(
            fs::read(dst.join("bin.dat")).unwrap(),
            vec![0xff, 0xfe, 0x00]
        );
        assert!(!dst.join("link.txt").exists());

        // Output inside input is rejected
        assert!(
            execute_inject_dir(&client, src.clone(), src.join("out"), false, false)
                .await
                .is_err()
        );

        // Resolution failure writes nothing
        let bad_src = tmp.path().join("bad_src");
        fs::create_dir_all(&bad_src).unwrap();
        fs::write(bad_src.join("x"), "{{ tacet://personal/Nope/password }}").unwrap();
        let bad_dst = tmp.path().join("bad_dst");
        assert!(
            execute_inject_dir(&client, bad_src, bad_dst.clone(), false, false)
                .await
                .is_err()
        );
        assert!(!bad_dst.exists());
    }

    // 4. In-place mode through the CLI, including dispatch and failure behavior.
    {
        use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};

        let src = tmp.path().join("in_place");
        fs::create_dir_all(src.join("nested")).unwrap();
        let template = src.join("nested/app.env");
        fs::write(&template, tpl_content).unwrap();
        fs::set_permissions(&template, fs::Permissions::from_mode(0o644)).unwrap();
        let plain = src.join("plain.txt");
        fs::write(&plain, "no secrets").unwrap();
        fs::set_permissions(&plain, fs::Permissions::from_mode(0o644)).unwrap();
        let plain_before = fs::metadata(&plain).unwrap();
        fs::write(src.join("binary"), [0xff, 0x00]).unwrap();
        let outside = tmp.path().join("outside.env");
        fs::write(&outside, tpl_content).unwrap();
        symlink(&outside, src.join("link.env")).unwrap();
        let outside_dir = tmp.path().join("outside_dir");
        fs::create_dir(&outside_dir).unwrap();
        fs::write(outside_dir.join("app.env"), tpl_content).unwrap();
        symlink(&outside_dir, src.join("linked_dir")).unwrap();

        for _ in 0..2 {
            let output = tokio::process::Command::new(env!("CARGO_BIN_EXE_tacet"))
                .arg("--socket")
                .arg(&socket_path)
                .args(["inject", "--in-dir"])
                .arg(&src)
                .arg("--in-place")
                .output()
                .await
                .unwrap();
            assert!(output.status.success(), "{:?}", output.stderr);
            assert!(output.stdout.is_empty());
        }
        assert_eq!(fs::read_to_string(&template).unwrap(), rendered);
        assert_eq!(fs::metadata(&template).unwrap().mode() & 0o777, 0o600);
        assert_eq!(fs::read_to_string(&plain).unwrap(), "no secrets");
        let plain_after = fs::metadata(&plain).unwrap();
        assert_eq!(plain_after.ino(), plain_before.ino());
        assert_eq!(plain_after.mode() & 0o777, 0o644);
        assert_eq!(fs::read(src.join("binary")).unwrap(), [0xff, 0x00]);
        assert!(fs::symlink_metadata(src.join("link.env"))
            .unwrap()
            .is_symlink());
        assert!(fs::symlink_metadata(src.join("linked_dir"))
            .unwrap()
            .is_symlink());
        assert_eq!(fs::read_to_string(&outside).unwrap(), tpl_content);
        assert_eq!(
            fs::read_to_string(outside_dir.join("app.env")).unwrap(),
            tpl_content
        );

        // A valid template sorts before the invalid one; neither may be changed.
        fs::write(&template, tpl_content).unwrap();
        fs::set_permissions(&template, fs::Permissions::from_mode(0o644)).unwrap();
        let bad_template = src.join("z-invalid.env");
        let bad_content = "{{ tacet://personal/NonExistentItem/password }}";
        fs::write(&bad_template, bad_content).unwrap();
        let output = tokio::process::Command::new(env!("CARGO_BIN_EXE_tacet"))
            .arg("--socket")
            .arg(&socket_path)
            .args(["inject", "--in-dir"])
            .arg(&src)
            .arg("--in-place")
            .output()
            .await
            .unwrap();
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert_eq!(fs::read_to_string(&template).unwrap(), tpl_content);
        assert_eq!(fs::metadata(&template).unwrap().mode() & 0o777, 0o644);
        assert_eq!(fs::read_to_string(&bad_template).unwrap(), bad_content);
    }

    // 5. Single-file in-place mode, using relative paths through the CLI.
    {
        use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
        use std::path::Path;

        async fn inject_file(socket: &Path, input: &Path) -> std::process::Output {
            tokio::process::Command::new(env!("CARGO_BIN_EXE_tacet"))
                .current_dir(input.parent().unwrap())
                .arg("--socket")
                .arg(socket)
                .args(["inject", "-i"])
                .arg(input.file_name().unwrap())
                .arg("--in-place")
                .output()
                .await
                .unwrap()
        }

        let dir = tmp.path().join("single_file");
        fs::create_dir(&dir).unwrap();
        let input = dir.join("config.env");
        fs::write(&input, tpl_content).unwrap();
        fs::set_permissions(&input, fs::Permissions::from_mode(0o644)).unwrap();
        let original = dir.join("original.env");
        fs::hard_link(&input, &original).unwrap();
        for _ in 0..2 {
            let output = inject_file(&socket_path, &input).await;
            assert!(output.status.success(), "{:?}", output.stderr);
            assert!(output.stdout.is_empty());
        }
        assert_eq!(fs::read_to_string(&input).unwrap(), rendered);
        assert_eq!(fs::metadata(&input).unwrap().mode() & 0o777, 0o600);
        assert_eq!(fs::read_to_string(&original).unwrap(), tpl_content);
        assert_eq!(fs::metadata(&original).unwrap().mode() & 0o777, 0o644);

        let plain = dir.join("plain.txt");
        fs::write(&plain, "unchanged").unwrap();
        fs::set_permissions(&plain, fs::Permissions::from_mode(0o644)).unwrap();
        let before = fs::metadata(&plain).unwrap();
        assert!(inject_file(&socket_path, &plain).await.status.success());
        assert_eq!(fs::read_to_string(&plain).unwrap(), "unchanged");
        assert_eq!(fs::metadata(&plain).unwrap().ino(), before.ino());
        assert_eq!(fs::metadata(&plain).unwrap().mode() & 0o777, 0o644);

        for (name, target) in [
            ("link.env", &original),
            ("broken.env", &dir.join("missing")),
        ] {
            let link = dir.join(name);
            symlink(target, &link).unwrap();
            let output = inject_file(&socket_path, &link).await;
            assert!(output.status.success(), "{:?}", output.stderr);
            assert!(output.stdout.is_empty());
            assert!(fs::symlink_metadata(&link).unwrap().is_symlink());
        }
        assert_eq!(fs::read_to_string(&original).unwrap(), tpl_content);
        assert!(!dir.join("missing").exists());

        let bad_content = format!("{tpl_content}{{{{ tacet://personal/Nope/password }}}}");
        fs::write(&input, &bad_content).unwrap();
        fs::set_permissions(&input, fs::Permissions::from_mode(0o644)).unwrap();
        let before = fs::metadata(&input).unwrap();
        let output = inject_file(&socket_path, &input).await;
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert_eq!(fs::read_to_string(&input).unwrap(), bad_content);
        assert_eq!(fs::metadata(&input).unwrap().ino(), before.ino());
        assert_eq!(fs::metadata(&input).unwrap().mode() & 0o777, 0o644);

        let binary = dir.join("binary");
        fs::write(&binary, [0xff, 0x00]).unwrap();
        for path in [&binary, &dir, &dir.join("missing")] {
            let output = inject_file(&socket_path, path).await;
            assert!(!output.status.success());
            assert!(output.stdout.is_empty());
        }
        assert_eq!(fs::read(&binary).unwrap(), [0xff, 0x00]);
        assert!(!dir.join("missing").exists());

        // A temporary-file collision must preserve both the input and existing file.
        fs::write(&input, tpl_content).unwrap();
        let occupied = dir.join(format!(".config.env.tacet-tmp-{}", std::process::id()));
        fs::write(&occupied, "occupied").unwrap();
        assert!(execute_inject_file_in_place(&client, input.clone())
            .await
            .is_err());
        assert_eq!(fs::read_to_string(&input).unwrap(), tpl_content);
        assert_eq!(fs::metadata(&input).unwrap().mode() & 0o777, 0o644);
        assert_eq!(fs::read_to_string(&occupied).unwrap(), "occupied");
    }

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
            deleted_date: None,
            key: None,
            attachments: None,
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
            deleted_date: None,
            key: None,
            attachments: None,
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
            deleted_date: None,
            key: None,
            attachments: None,
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
