# transaction_metadata.py
from api.models import TransactionMetadata

def create_transaction_metadata(transaction_id: str, **kwargs):
    # If exists, update; otherwise create
    obj, created = TransactionMetadata.objects.get_or_create(transaction_id=transaction_id, defaults={})
    for k, v in kwargs.items():
        setattr(obj, k, v)
    obj.save()
    return obj

def update_transaction_metadata(transaction_id: str, **kwargs):
    obj = TransactionMetadata.objects.filter(transaction_id=transaction_id).first()
    if not obj:
        obj = TransactionMetadata(transaction_id=transaction_id)
    for k, v in kwargs.items():
        setattr(obj, k, v)
    obj.save()
    return obj

def get_transaction_metadata(transaction_id: str):
    return TransactionMetadata.objects.filter(transaction_id=transaction_id).first()
