import hashlib
import time

# In-memory store for audit logs
_audit_store = []

def log_event(transaction_id: str, event_type: str, details=None):
    """
    Log an event linked to a transaction_id.
    Stateless relative to user.
    """
    timestamp = time.time()
    record = {
        "transaction_id": transaction_id,
        "event_type": event_type,
        "details": details or {},
        "timestamp": timestamp
    }
    # Add hash-chain for tamper-evidence
    prev_hash = _audit_store[-1]["hash"] if _audit_store else ""
    record_hash = hashlib.sha256((str(record) + prev_hash).encode()).hexdigest()
    record["hash"] = record_hash
    _audit_store.append(record)
    return record

def retrieve_log(transaction_id: str):
    """Retrieve all logs linked to a transaction_id"""
    return [r for r in _audit_store if r["transaction_id"] == transaction_id]

def hash_chain_append(log: dict):
    """Append a log with hash chaining"""
    prev_hash = _audit_store[-1]["hash"] if _audit_store else ""
    record_hash = hashlib.sha256((str(log) + prev_hash).encode()).hexdigest()
    log["hash"] = record_hash
    _audit_store.append(log)
    return log
