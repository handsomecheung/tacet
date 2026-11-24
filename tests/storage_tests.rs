use chrono::Utc;
use std::fs;
use tacet::crypto::kdf::KdfParams;
use tacet::error::StorageError;
use tacet::storage::paths::StoragePaths;
use tacet::storage::session::SessionMetadata;
use tacet::storage::vault_cache::EncryptedVaultCache;
use tacet::upstream::models::{CipherResponse, SyncResponse};
use tempfile::tempdir;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

#[test]
fn test_session_lifecycle_and_permissions() {
    let tmp = tempdir().expect("Failed to create tempdir");
    let config_dir = tmp.path().join("config");
    let cache_dir = tmp.path().join("cache");

    let paths = StoragePaths::custom(config_dir.clone(), cache_dir.clone());

    // Initially not exists
    assert!(!SessionMetadata::exists(&paths));
    assert!(matches!(
        SessionMetadata::load(&paths).unwrap_err(),
        StorageError::SessionNotFound
    ));

    let session = SessionMetadata {
        server_url: "https://vault.example.com".to_string(),
        email: "alice@example.com".to_string(),
        api_client_id: None,
        access_token: "jwt_token_123".to_string(),
        refresh_token: Some("refresh_abc".to_string()),
        expires_at: Some(Utc::now()),
        kdf_params: KdfParams::pbkdf2(600_000),
        protected_symmetric_key: Some("2.iv|key_ct|mac".to_string()),
        protected_rsa_private_key: None,
        user_id: Some("user-uuid".to_string()),
        last_synced: Some(Utc::now()),
    };

    // Save session
    session.save(&paths).expect("Save failed");
    assert!(SessionMetadata::exists(&paths));

    // Verify Unix permissions
    #[cfg(unix)]
    {
        let dir_meta = fs::metadata(&config_dir).unwrap();
        assert_eq!(dir_meta.permissions().mode() & 0o777, 0o700);

        let file_meta = fs::metadata(paths.session_file()).unwrap();
        assert_eq!(file_meta.permissions().mode() & 0o777, 0o600);
    }

    // Load and verify fields
    let loaded = SessionMetadata::load(&paths).expect("Load failed");
    assert_eq!(loaded.server_url, session.server_url);
    assert_eq!(loaded.email, session.email);
    assert_eq!(loaded.access_token, session.access_token);
    assert_eq!(loaded.refresh_token, session.refresh_token);
    assert_eq!(
        loaded.protected_symmetric_key,
        session.protected_symmetric_key
    );

    let mut api_session = session.clone();
    api_session.api_client_id = Some("user.api-user".into());
    api_session.save(&paths).unwrap();
    let loaded = SessionMetadata::load(&paths).unwrap();
    assert_eq!(loaded.api_client_id, api_session.api_client_id);
    let mut legacy = serde_json::to_value(&api_session).unwrap();
    legacy.as_object_mut().unwrap().remove("api_client_id");
    let legacy: SessionMetadata = serde_json::from_value(legacy).unwrap();
    assert!(legacy.api_client_id.is_none());

    // Clear session
    SessionMetadata::clear(&paths).expect("Clear failed");
    assert!(!SessionMetadata::exists(&paths));
}

#[test]
fn test_vault_cache_lifecycle_and_permissions() {
    let tmp = tempdir().expect("Failed to create tempdir");
    let config_dir = tmp.path().join("config");
    let cache_dir = tmp.path().join("cache");

    let paths = StoragePaths::custom(config_dir, cache_dir.clone());

    assert!(!EncryptedVaultCache::exists(&paths));
    assert!(matches!(
        EncryptedVaultCache::load(&paths).unwrap_err(),
        StorageError::VaultCacheNotFound
    ));

    let sync_data = SyncResponse {
        profile: None,
        folders: vec![],
        collections: vec![],
        ciphers: vec![
            CipherResponse {
                deleted_date: None,
                key: None,
                attachments: None,
                id: "c1".to_string(),
                organization_id: None,
                folder_id: None,
                collection_ids: vec![],
                cipher_type: 1,
                name: "2.iv|name1|mac".to_string(),
                notes: None,
                favorite: Some(true),
                login: None,
                fields: None,
            },
            CipherResponse {
                deleted_date: None,
                key: None,
                attachments: None,
                id: "c2".to_string(),
                organization_id: None,
                folder_id: None,
                collection_ids: vec![],
                cipher_type: 1,
                name: "2.iv|name2|mac".to_string(),
                notes: None,
                favorite: None,
                login: None,
                fields: None,
            },
        ],
    };

    let cache = EncryptedVaultCache::new(sync_data);
    assert_eq!(cache.item_count(), 2);

    // Save cache
    cache.save(&paths).expect("Save cache failed");
    assert!(EncryptedVaultCache::exists(&paths));

    // Verify Unix permissions
    #[cfg(unix)]
    {
        let dir_meta = fs::metadata(&cache_dir).unwrap();
        assert_eq!(dir_meta.permissions().mode() & 0o777, 0o700);

        let file_meta = fs::metadata(paths.vault_cache_file()).unwrap();
        assert_eq!(file_meta.permissions().mode() & 0o777, 0o600);
    }

    // Load and verify
    let loaded = EncryptedVaultCache::load(&paths).expect("Load cache failed");
    assert_eq!(loaded.item_count(), 2);
    assert_eq!(loaded.data.ciphers[0].id, "c1");
    assert_eq!(loaded.data.ciphers[0].name, "2.iv|name1|mac");

    // Clear cache
    EncryptedVaultCache::clear(&paths).expect("Clear cache failed");
    assert!(!EncryptedVaultCache::exists(&paths));
}

#[test]
fn test_cached_trash_is_excluded_and_archived_items_remain_available() {
    let tmp = tempdir().unwrap();
    let paths = StoragePaths::custom(tmp.path().join("config"), tmp.path().join("cache"));
    paths.ensure_dirs().unwrap();
    let cache = serde_json::json!({
        "updated_at": Utc::now(),
        "data": {
            "ciphers": [
                {"id": "active", "type": 1, "name": "2.iv|name|mac"},
                {
                    "id": "trash", "type": 1, "name": "2.iv|name|mac",
                    "deletedDate": "2026-11-01T00:00:00Z"
                },
                {
                    "id": "archived", "type": 1, "name": "2.iv|name|mac",
                    "archivedDate": "2026-11-01T00:00:00Z"
                }
            ]
        }
    });
    StoragePaths::write_secure_file(
        paths.vault_cache_file(),
        &serde_json::to_vec(&cache).unwrap(),
    )
    .unwrap();

    let state =
        tacet::daemon::DaemonState::new(paths.clone(), std::time::Duration::from_secs(1800));
    let vault = state.vault.try_read().unwrap();
    let ciphers = &vault.as_ref().unwrap().ciphers;
    assert_eq!(ciphers.len(), 2);
    assert_eq!(ciphers[0].id, "active");
    assert_eq!(ciphers[1].id, "archived");

    let loaded = EncryptedVaultCache::load(&paths).unwrap();
    loaded.save(&paths).unwrap();
    let saved: serde_json::Value =
        serde_json::from_slice(&fs::read(paths.vault_cache_file()).unwrap()).unwrap();
    assert_eq!(saved["data"]["ciphers"].as_array().unwrap().len(), 2);
}
