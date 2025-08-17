# audit_logs.py
import hashlib
import json
import logging
from api.models import AuditLog

logger = logging.getLogger("securecipher.audit")

def _compute_hash(record_dict: dict, prev_hash: str = "") -> str:
    stable = json.dumps(record_dict, sort_keys=True, separators=(",", ":"))
    h = hashlib.sha256()
    h.update(stable.encode())
    if prev_hash:
        h.update(prev_hash.encode())
    return h.hexdigest()

def log_event(transaction_id: str, event_type: str, details: dict = None, actor: str = "middleware"):
    details = details or {}
    # find last record for transaction to chain
    last = AuditLog.objects.filter(transaction_id=transaction_id).order_by("-timestamp").first()
    prev_hash = last.record_hash if last else ""
    record = {
        "transaction_id": transaction_id,
        "event_type": event_type,
        "details": details,
        "actor": actor
    }
    record_hash = _compute_hash(record, prev_hash)
    db_obj = AuditLog.objects.create(
        transaction_id=transaction_id,
        event_type=event_type,
        details=details,
        actor=actor,
        prev_hash=prev_hash,
        record_hash=record_hash
    )
    logger.debug("AuditLog created id=%s tx=%s event=%s", db_obj.id, transaction_id, event_type)
    return db_obj

def retrieve_log(transaction_id: str):
    qs = AuditLog.objects.filter(transaction_id=transaction_id).order_by("timestamp")
    return list(qs.values("transaction_id", "event_type", "details", "actor", "timestamp", "prev_hash", "record_hash"))
