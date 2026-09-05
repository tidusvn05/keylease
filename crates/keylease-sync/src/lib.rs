//! Deterministic ciphertext-only sync simulation used to pin Phase 0 semantics.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SyncMutation {
    pub mutation_id: String,
    pub device_id: String,
    pub actor_id: String,
    pub object_id: String,
    pub base_revision: u64,
    pub result_revision: u64,
    pub idempotency_key: String,
    pub ciphertext_digest: String,
    pub tombstone: bool,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ObjectState {
    pub revision: u64,
    pub ciphertext_digest: String,
    pub tombstone: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SyncConflict {
    pub object_id: String,
    pub current_revision: u64,
    pub rejected_base_revision: u64,
    pub winner_mutation_id: String,
    pub conflicting_mutation_id: String,
}

#[derive(Debug, Clone, Default)]
pub struct DeviceState {
    pub objects: BTreeMap<String, ObjectState>,
    pub mutations: Vec<SyncMutation>,
    seen_idempotency: BTreeMap<String, String>,
    pub conflicts: Vec<SyncConflict>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApplyResult {
    Applied,
    Replay,
    Conflict(SyncConflict),
    IdempotencyConflict,
}

impl DeviceState {
    pub fn apply(&mut self, mutation: SyncMutation) -> ApplyResult {
        if let Some(digest) = self.seen_idempotency.get(&mutation.idempotency_key) {
            return if digest == &mutation.ciphertext_digest {
                ApplyResult::Replay
            } else {
                ApplyResult::IdempotencyConflict
            };
        }
        let current = self
            .objects
            .get(&mutation.object_id)
            .cloned()
            .unwrap_or(ObjectState {
                revision: 0,
                ciphertext_digest: String::new(),
                tombstone: false,
            });
        if current.revision != mutation.base_revision
            || mutation.result_revision != mutation.base_revision + 1
        {
            let winner = self
                .mutations
                .iter()
                .rev()
                .find(|m| m.object_id == mutation.object_id)
                .map(|m| m.mutation_id.clone())
                .unwrap_or_else(|| "local-state".into());
            let conflict = SyncConflict {
                object_id: mutation.object_id.clone(),
                current_revision: current.revision,
                rejected_base_revision: mutation.base_revision,
                winner_mutation_id: winner,
                conflicting_mutation_id: mutation.mutation_id.clone(),
            };
            self.conflicts.push(conflict.clone());
            return ApplyResult::Conflict(conflict);
        }
        self.seen_idempotency.insert(
            mutation.idempotency_key.clone(),
            mutation.ciphertext_digest.clone(),
        );
        self.objects.insert(
            mutation.object_id.clone(),
            ObjectState {
                revision: mutation.result_revision,
                ciphertext_digest: mutation.ciphertext_digest.clone(),
                tombstone: mutation.tombstone,
            },
        );
        self.mutations.push(mutation);
        ApplyResult::Applied
    }
}

/// Replays both mutation logs in stable order and returns equal materialized states.
pub fn simulate_pair(a: &DeviceState, b: &DeviceState) -> (DeviceState, DeviceState) {
    let mut all: Vec<_> = a.mutations.iter().chain(&b.mutations).cloned().collect();
    let mut ids = BTreeSet::new();
    all.retain(|m| ids.insert(m.mutation_id.clone()));
    all.sort_by(|x, y| {
        (&x.created_at, &x.device_id, &x.mutation_id).cmp(&(
            &y.created_at,
            &y.device_id,
            &y.mutation_id,
        ))
    });
    let mut left = DeviceState::default();
    let mut right = DeviceState::default();
    for mutation in all {
        let _ = left.apply(mutation.clone());
        let _ = right.apply(mutation);
    }
    (left, right)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn mutation(id: &str, device: &str, base: u64, digest: &str) -> SyncMutation {
        SyncMutation {
            mutation_id: id.into(),
            device_id: device.into(),
            actor_id: "agent".into(),
            object_id: "item_1".into(),
            base_revision: base,
            result_revision: base + 1,
            idempotency_key: id.into(),
            ciphertext_digest: digest.into(),
            tombstone: false,
            created_at: DateTime::parse_from_rfc3339("2026-09-05T10:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
        }
    }
    #[test]
    fn two_device_conflict_is_deterministic_and_secret_values_never_merge() {
        let mut a = DeviceState::default();
        let mut b = DeviceState::default();
        assert_eq!(
            a.apply(mutation("m-a", "a", 0, "cipher-a")),
            ApplyResult::Applied
        );
        assert_eq!(
            b.apply(mutation("m-b", "b", 0, "cipher-b")),
            ApplyResult::Applied
        );
        let (left, right) = simulate_pair(&a, &b);
        assert_eq!(left.objects, right.objects);
        assert_eq!(left.conflicts, right.conflicts);
        assert_eq!(left.objects["item_1"].ciphertext_digest, "cipher-a");
        assert_eq!(left.conflicts.len(), 1);
    }
    #[test]
    fn idempotency_replay_is_not_a_second_mutation() {
        let mut d = DeviceState::default();
        let m = mutation("m", "a", 0, "cipher");
        assert_eq!(d.apply(m.clone()), ApplyResult::Applied);
        assert_eq!(d.apply(m), ApplyResult::Replay);
        assert_eq!(d.mutations.len(), 1);
    }
}
