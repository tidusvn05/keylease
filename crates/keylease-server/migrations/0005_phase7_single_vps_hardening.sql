ALTER TABLE audit_event_index
    ADD COLUMN previous_chain_digest_sha256 TEXT,
    ADD COLUMN chain_position BIGINT;

ALTER TABLE audit_event_index
    ADD CONSTRAINT audit_event_chain_position_positive
        CHECK (chain_position IS NULL OR chain_position > 0),
    ADD CONSTRAINT audit_event_chain_metadata_complete
        CHECK (
            (chain_position IS NULL AND previous_chain_digest_sha256 IS NULL)
            OR
            (chain_position IS NOT NULL AND previous_chain_digest_sha256 IS NOT NULL AND chain_digest_sha256 IS NOT NULL)
        );

CREATE UNIQUE INDEX audit_event_project_chain_position_idx
    ON audit_event_index(project_id, chain_position)
    WHERE chain_position IS NOT NULL;
