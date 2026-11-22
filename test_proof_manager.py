
import sqlite3

import pytest

from proof_manager import (
    ProofError,
    cleanup_expired_proofs,
    create_proof,
    create_proof_keypair,
    delete_proof_key,
    load_private_key,
    verify_and_consume_proof,
)
from secret_store import MemorySecretStore


NOW = 1_700_000_000
SESSION = "session-123"


@pytest.fixture
def proof_db():
    conn = sqlite3.connect(":memory:")

    conn.execute(
        """
        CREATE TABLE proof_requests (
            id INTEGER PRIMARY KEY,
            session_id TEXT NOT NULL,
            jti TEXT NOT NULL,
            request_id TEXT NOT NULL,
            operation TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            UNIQUE(session_id, jti)
        )
        """
    )

    yield conn

    conn.close()


@pytest.fixture
def proof_environment():
    store = MemorySecretStore()

    keys = create_proof_keypair(
        store,
        SESSION,
    )

    private_key = load_private_key(
        store,
        SESSION,
    )

    return store, keys, private_key


class TestProofKeypair:

    def test_keypair_creation(self, proof_environment):
        store, keys, private_key = proof_environment

        assert keys["key_id"]
        assert keys["public_key"]

        assert private_key is not None

        assert store.get(f"proof-{SESSION}") is not None

    def test_second_keypair_creation_is_rejected(
        self,
        proof_environment,
    ):
        store, keys, private_key = proof_environment

        with pytest.raises(ProofError) as caught:
            create_proof_keypair(store, SESSION)

        assert caught.value.code == "key_exists"

    def test_missing_private_key_is_rejected(self):
        store = MemorySecretStore()

        with pytest.raises(ProofError) as caught:
            load_private_key(store, SESSION)

        assert caught.value.code == "key_missing"

    def test_delete_private_key(self, proof_environment):
        store, keys, private_key = proof_environment

        delete_proof_key(store, SESSION)

        assert store.get(f"proof-{SESSION}") is None


class TestProofCreation:

    def test_create_proof(self, proof_environment):
        store, keys, private_key = proof_environment

        proof = create_proof(
            private_key,
            SESSION,
            "access_refresh",
            now=NOW,
        )

        assert isinstance(proof, str)
        assert "." in proof

    def test_invalid_operation(self, proof_environment):
        store, keys, private_key = proof_environment

        with pytest.raises(ValueError):
            create_proof(
                private_key,
                SESSION,
                "invalid_operation",
                now=NOW,
            )


class TestProofVerification:

    def test_valid_proof_is_accepted(
        self,
        proof_db,
        proof_environment,
    ):
        store, keys, private_key = proof_environment

        proof = create_proof(
            private_key,
            SESSION,
            "access_refresh",
            now=NOW,
        )

        result = verify_and_consume_proof(
            proof_db,
            keys["public_key"],
            proof,
            SESSION,
            "access_refresh",
            now=NOW,
        )

        assert result["sid"] == SESSION
        assert result["op"] == "access_refresh"

    def test_replayed_proof_is_rejected(
        self,
        proof_db,
        proof_environment,
    ):
        store, keys, private_key = proof_environment

        proof = create_proof(
            private_key,
            SESSION,
            "access_refresh",
            now=NOW,
        )

        verify_and_consume_proof(
            proof_db,
            keys["public_key"],
            proof,
            SESSION,
            "access_refresh",
            now=NOW,
        )

        with pytest.raises(ProofError) as caught:
            verify_and_consume_proof(
                proof_db,
                keys["public_key"],
                proof,
                SESSION,
                "access_refresh",
                now=NOW,
            )

        assert caught.value.code == "replay"

    def test_wrong_session_is_rejected(
        self,
        proof_db,
        proof_environment,
    ):
        store, keys, private_key = proof_environment

        proof = create_proof(
            private_key,
            SESSION,
            "access_refresh",
            now=NOW,
        )

        with pytest.raises(ProofError) as caught:
            verify_and_consume_proof(
                proof_db,
                keys["public_key"],
                proof,
                "another-session",
                "access_refresh",
                now=NOW,
            )

        assert caught.value.code == "wrong_session"

    def test_wrong_operation_is_rejected(
        self,
        proof_db,
        proof_environment,
    ):
        store, keys, private_key = proof_environment

        proof = create_proof(
            private_key,
            SESSION,
            "access_refresh",
            now=NOW,
        )

        with pytest.raises(ProofError) as caught:
            verify_and_consume_proof(
                proof_db,
                keys["public_key"],
                proof,
                SESSION,
                "refresh_rotation",
                now=NOW,
            )

        assert caught.value.code == "wrong_operation"

    def test_expired_proof_is_rejected(
        self,
        proof_db,
        proof_environment,
    ):
        store, keys, private_key = proof_environment

        proof = create_proof(
            private_key,
            SESSION,
            "access_refresh",
            now=NOW,
        )

        with pytest.raises(ProofError) as caught:
            verify_and_consume_proof(
                proof_db,
                keys["public_key"],
                proof,
                SESSION,
                "access_refresh",
                now=NOW + 61,
            )

        assert caught.value.code == "expired"

    def test_modified_proof_is_rejected(
        self,
        proof_db,
        proof_environment,
    ):
        store, keys, private_key = proof_environment

        proof = create_proof(
            private_key,
            SESSION,
            "access_refresh",
            now=NOW,
        )

        modified = proof[:-1] + (
            "A" if proof[-1] != "A" else "B"
        )

        with pytest.raises(ProofError):
            verify_and_consume_proof(
                proof_db,
                keys["public_key"],
                modified,
                SESSION,
                "access_refresh",
                now=NOW,
            )


class TestProofCleanup:

    def test_cleanup_removes_old_proofs(self, proof_db):
        proof_db.execute(
            """
            INSERT INTO proof_requests (
                session_id,
                jti,
                request_id,
                operation,
                created_at
            )
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                SESSION,
                "old-jti",
                "old-request",
                "access_refresh",
                NOW,
            ),
        )

        removed = cleanup_expired_proofs(
            proof_db,
            now=NOW + 1000,
        )

        assert removed == 1

        count = proof_db.execute(
            "SELECT COUNT(*) FROM proof_requests"
        ).fetchone()[0]

        assert count == 0
