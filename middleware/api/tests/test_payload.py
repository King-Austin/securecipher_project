import pytest
import json
import time
from django.urls import reverse
from django.test import Client
from modules.crypto_engine import perform_ecdh, derive_session_key_from_peer, aes256gcm_encrypt

client = Client()

# ---- Helpers ----
def make_valid_envelope(transaction_data: dict):
    """Simulate frontend encryption for a valid packet."""
    ephemeral_priv, ephemeral_pub_der = perform_ecdh()
    keys = derive_session_key_from_peer(ephemeral_priv, ephemeral_pub_der)  # middleware pub would normally be used
    ciphertext, iv = aes256gcm_encrypt(transaction_data, keys["aes_key"])
    return {
        "ciphertext": ciphertext,
        "iv": iv,
        "ephemeral_public_key": ephemeral_pub_der.hex()
    }

# ---- Core Tests ----
@pytest.mark.django_db
def test_valid_payload_success():
    data = {"email": "alice@example.com", "phone_number": "08012345678", "timestamp": time.time(), "nonce": "xyz123"}
    envelope = make_valid_envelope(data)

    response = client.post(reverse("secure_gateway"), data=json.dumps(envelope), content_type="application/json")

    assert response.status_code == 200
    body = response.json()
    assert body.get("status") == "ok"

@pytest.mark.django_db
def test_malformed_payload_iv():
    data = {"email": "bob@example.com", "phone_number": "08098765432", "timestamp": time.time(), "nonce": "abc456"}
    envelope = make_valid_envelope(data)
    envelope["iv"] = "bad_iv_value"  # Corrupt the IV

    response = client.post(reverse("secure_gateway"), data=json.dumps(envelope), content_type="application/json")

    assert response.status_code == 400
    assert "Invalid IV" in response.json()["error"]

@pytest.mark.django_db
def test_replay_attack_nonce():
    """Simulate sending same payload twice."""
    data = {"email": "carol@example.com", "phone_number": "08123456789", "timestamp": time.time(), "nonce": "dup123"}
    envelope = make_valid_envelope(data)

    first = client.post(reverse("secure_gateway"), data=json.dumps(envelope), content_type="application/json")
    second = client.post(reverse("secure_gateway"), data=json.dumps(envelope), content_type="application/json")

    assert second.status_code == 400
    assert "Replay detected" in second.json()["error"]

@pytest.mark.benchmark
def test_latency_benchmark(benchmark):
    data = {"email": "perf@example.com", "phone_number": "08011112222", "timestamp": time.time(), "nonce": "lat123"}
    envelope = make_valid_envelope(data)

    def send_request():
        client.post(reverse("secure_gateway"), data=json.dumps(envelope), content_type="application/json")

    result = benchmark(send_request)
    assert result is not None
