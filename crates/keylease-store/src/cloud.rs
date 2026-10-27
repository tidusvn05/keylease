//! Local state of the cloud relay (ADR 0006): one keyed record table, and
//! encryption of the relay keys under a subkey of the vault key.

use super::*;
use keylease_crypto::sealed::{SymmetricBox, open_symmetric, seal_symmetric};

pub mod record {
    /// The link to a cloud and this member's public identity (one record).
    pub const LINK: &str = "link";
    /// Owner: a node whose keys this device verified.
    pub const NODE: &str = "node";
    /// Owner: an invite whose secret half verifies the joining node.
    pub const INVITE: &str = "invite";
    /// Owner: an item or project share.
    pub const SHARE: &str = "share";
    /// Owner: the revision of one item last published under a share
    /// (`SHARE_ID/ITEM_ID`).
    pub const SHARE_ITEM: &str = "share_item";
    /// Node: an item received through a share (`SHARE_ID/OWNER_ITEM_ID`).
    pub const RECEIVED: &str = "received";
    /// The revision of one of this member's items last backed up.
    pub const BACKUP: &str = "backup";
    /// A share request (owner: received; node: sent).
    pub const REQUEST: &str = "request";
    /// A message id already applied.
    pub const APPLIED: &str = "applied";
    /// A message waiting to be sent.
    pub const OUTBOX: &str = "outbox";
}

fn local_secret_key(unlocked: &UnlockedVault) -> SecretKey {
    SecretKey::from_bytes(keyed_digest(
        &unlocked.vault_key,
        "keylease-local-secret-key-v1",
        unlocked.vault_id.0.as_bytes(),
    ))
}

impl NativeStore {
    /// Encrypts `plaintext` for this vault only, bound to `label`.
    pub fn seal_local_secret(
        &self,
        unlocked: &UnlockedVault,
        label: &str,
        plaintext: &[u8],
    ) -> Result<String> {
        json(&seal_symmetric(
            &local_secret_key(unlocked),
            plaintext,
            format!("keylease-local-secret-v1:{label}").as_bytes(),
        )?)
    }

    pub fn open_local_secret(
        &self,
        unlocked: &UnlockedVault,
        label: &str,
        sealed: &str,
    ) -> Result<Zeroizing<Vec<u8>>> {
        let sealed: SymmetricBox =
            serde_json::from_str(sealed).map_err(|_| KeyLeaseError::Crypto)?;
        open_symmetric(
            &local_secret_key(unlocked),
            &sealed,
            format!("keylease-local-secret-v1:{label}").as_bytes(),
        )
    }

    pub fn cloud_put(&self, kind: &str, id: &str, record_json: &str) -> Result<()> {
        let connection = self.connection.lock().map_err(|_| KeyLeaseError::Storage)?;
        connection
            .execute(
                "INSERT INTO cloud_records(kind,id,record_json,updated_at) VALUES(?1,?2,?3,?4) ON CONFLICT(kind,id) DO UPDATE SET record_json=excluded.record_json,updated_at=excluded.updated_at",
                params![kind, id, record_json, Utc::now().to_rfc3339()],
            )
            .map_err(|_| KeyLeaseError::Storage)?;
        Ok(())
    }

    /// Inserts only when absent; returns whether it inserted.
    pub fn cloud_insert(&self, kind: &str, id: &str, record_json: &str) -> Result<bool> {
        let connection = self.connection.lock().map_err(|_| KeyLeaseError::Storage)?;
        let changed = connection
            .execute(
                "INSERT INTO cloud_records(kind,id,record_json,updated_at) VALUES(?1,?2,?3,?4) ON CONFLICT(kind,id) DO NOTHING",
                params![kind, id, record_json, Utc::now().to_rfc3339()],
            )
            .map_err(|_| KeyLeaseError::Storage)?;
        Ok(changed == 1)
    }

    pub fn cloud_get(&self, kind: &str, id: &str) -> Result<Option<String>> {
        let connection = self.connection.lock().map_err(|_| KeyLeaseError::Storage)?;
        connection
            .query_row(
                "SELECT record_json FROM cloud_records WHERE kind=?1 AND id=?2",
                params![kind, id],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| KeyLeaseError::Storage)
    }

    /// Records of `kind` whose id starts with `prefix`, ordered by id.
    pub fn cloud_list(&self, kind: &str, prefix: &str) -> Result<Vec<(String, String)>> {
        let connection = self.connection.lock().map_err(|_| KeyLeaseError::Storage)?;
        let mut statement = connection
            .prepare(
                "SELECT id,record_json FROM cloud_records WHERE kind=?1 AND substr(id,1,length(?2))=?2 ORDER BY id",
            )
            .map_err(|_| KeyLeaseError::Storage)?;
        statement
            .query_map(params![kind, prefix], |row| Ok((row.get(0)?, row.get(1)?)))
            .map_err(|_| KeyLeaseError::Storage)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|_| KeyLeaseError::Storage)
    }

    pub fn cloud_delete(&self, kind: &str, id: &str) -> Result<()> {
        let connection = self.connection.lock().map_err(|_| KeyLeaseError::Storage)?;
        connection
            .execute(
                "DELETE FROM cloud_records WHERE kind=?1 AND id=?2",
                params![kind, id],
            )
            .map_err(|_| KeyLeaseError::Storage)?;
        Ok(())
    }

    /// Ids of the items currently in the vault, with their revisions, without
    /// decrypting them.
    pub fn item_revisions(&self) -> Result<Vec<(String, u64)>> {
        let connection = self.connection.lock().map_err(|_| KeyLeaseError::Storage)?;
        let mut statement = connection
            .prepare("SELECT item_id,revision FROM items ORDER BY item_id")
            .map_err(|_| KeyLeaseError::Storage)?;
        statement
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .map_err(|_| KeyLeaseError::Storage)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|_| KeyLeaseError::Storage)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_secrets_are_bound_to_vault_and_label_and_records_round_trip() {
        let directory = tempfile::tempdir().unwrap();
        let store = NativeStore::open(directory.path().join("v.sqlite")).unwrap();
        let unlocked = store.initialize(b"correct horse battery").unwrap();
        let sealed = store
            .seal_local_secret(&unlocked, "relay-keys", b"secret")
            .unwrap();
        assert_eq!(
            store
                .open_local_secret(&unlocked, "relay-keys", &sealed)
                .unwrap()
                .as_slice(),
            b"secret"
        );
        assert!(
            store
                .open_local_secret(&unlocked, "other", &sealed)
                .is_err()
        );

        assert!(store.cloud_insert(record::APPLIED, "m1", "{}").unwrap());
        assert!(!store.cloud_insert(record::APPLIED, "m1", "{}").unwrap());
        store.cloud_put(record::SHARE_ITEM, "s1/i1", "1").unwrap();
        store.cloud_put(record::SHARE_ITEM, "s1/i2", "2").unwrap();
        store.cloud_put(record::SHARE_ITEM, "s2/i1", "3").unwrap();
        assert_eq!(
            store.cloud_list(record::SHARE_ITEM, "s1/").unwrap().len(),
            2
        );
        store.cloud_delete(record::SHARE_ITEM, "s1/i1").unwrap();
        assert_eq!(
            store
                .cloud_get(record::SHARE_ITEM, "s1/i2")
                .unwrap()
                .as_deref(),
            Some("2")
        );
        assert!(
            store
                .cloud_get(record::SHARE_ITEM, "s1/i1")
                .unwrap()
                .is_none()
        );
    }
}
