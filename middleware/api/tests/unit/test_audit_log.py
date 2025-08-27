# test_audit_logs.py
import pytest
from modules.audit_logs import log_event, retrieve_log, _compute_hash



def test_first_log_has_empty_prev_hash():
    """The first log in a transaction should have no prev_hash (root of chain)."""
    txid = "tx123"
    log = log_event(txid, event_type="INIT", actor="client")
    assert log.prev_hash == ""
    assert log.record_hash is not None and len(log.record_hash) == 64  # sha256 hex


def test_chain_integrity_between_logs():
    """Each new log should chain correctly using prev_hash = last.record_hash."""
    txid = "tx456"
    log1 = log_event(txid, event_type="INIT")
    log2 = log_event(txid, event_type="PROCESS")
    log3 = log_event(txid, event_type="COMPLETE")

    # check chaining
    assert log2.prev_hash == log1.record_hash
    assert log3.prev_hash == log2.record_hash


def test_retrieve_log_returns_ordered_chain():
    """retrieve_log should return logs ordered by timestamp, forming a consistent chain."""
    txid = "tx789"
    log_event(txid, event_type="STEP1")
    log_event(txid, event_type="STEP2")
    log_event(txid, event_type="STEP3")

    logs = retrieve_log(txid)
    assert len(logs) == 3
    # timestamp is ordered
    timestamps = [l["timestamp"] for l in logs]
    assert timestamps == sorted(timestamps)


def test_tamper_detection_with_recomputed_hash():
    """If a log is tampered with, recomputed hash won't match the stored record_hash."""
    txid = "tx999"
    log = log_event(txid, event_type="REGISTER", actor="client")

    # simulate tampering: change actor field
    log.actor = "attacker"
    tampered_hash = _compute_hash(
        {"transaction_id": log.transaction_id, "event_type": log.event_type, "actor": log.actor},
        log.prev_hash,
    )

    # record_hash should not match after tampering
    assert tampered_hash != log.record_hash
