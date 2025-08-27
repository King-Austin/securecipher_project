import pytest, os, base64, json, time, copy
from cryptography.hazmat.primitives import serialization
from modules import crypto_engine as ce


# ---------- Fixtures ----------

@pytest.fixture
def ecdsa_keypair():
    priv, _ = ce.generate_ec_keypair()
    pub = priv.public_key()
    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    pub_pem = pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    return priv, priv_pem, pub, pub_pem


@pytest.fixture
def aes_key():
    return os.urandom(32)


@pytest.fixture
def realistic_payload_for_tests():
    """
    Mimics frontend SecureCipher payload:
    {
        target,
        transaction_data,
        client_signature,
        client_public_key,
        nonce,
        timestamp
    }
    """
    transaction_data = {
        "amount": 1250.50,
        "recipient": {
            "id": 54321,
            "account": "0099887766",
        }
    }

    # A realistic payload for tests
    payload = {
        "target": "transfer",
        "transaction_data": transaction_data,
        "client_signature": "PLACEHOLDER_SIG",
        "client_public_key": "PLACEHOLDER_KEY",
        "nonce": os.urandom(8).hex(),
        "timestamp": int(time.time())
    }

    return payload


# ---------- Hash Tests ----------

def test_hash_data_consistency(realistic_payload_for_tests):
    h1 = ce.hash_data(realistic_payload_for_tests)
    h2 = ce.hash_data(json.dumps(realistic_payload_for_tests))
    print("[Hash] digest (trunc):", h1[:32], "…")
    assert h1 == h2
    assert len(h1) == 64


# ---------- ECDSA Tests ----------

def test_ecdsa_sign_and_verify(ecdsa_keypair, realistic_payload_for_tests):
    _, priv_pem, _, pub_pem = ecdsa_keypair
    payload = copy.deepcopy(realistic_payload_for_tests)

    sig = ce.ecdsa_sign(payload["transaction_data"], priv_pem)
    payload["client_signature"] = sig
    result = ce.ecdsa_verify(payload["transaction_data"], sig, pub_pem)

    print("[ECDSA] target:", payload["target"], "| sig (trunc):", sig[:40], "…", "| ok?", result)
    assert result is True


def test_ecdsa_verify_fails_with_tampered_payload(ecdsa_keypair, realistic_payload_for_tests):
    _, priv_pem, _, pub_pem = ecdsa_keypair
    payload = copy.deepcopy(realistic_payload_for_tests)

    sig = ce.ecdsa_sign(payload["transaction_data"], priv_pem)

    tampered = copy.deepcopy(payload)
    tampered["transaction_data"]["amount"] += 1000  # tamper amount
    result = ce.ecdsa_verify(tampered["transaction_data"], sig, pub_pem)

    print("[ECDSA Tamper] orig:", payload["transaction_data"]["amount"],
          "-> tampered:", tampered["transaction_data"]["amount"], "| ok?", result)
    assert result is False


# ---------- AES-GCM Tests ----------

def test_aes256gcm_encrypt_decrypt(aes_key, realistic_payload_for_tests):
    payload = copy.deepcopy(realistic_payload_for_tests)
    envelope = ce.aes256gcm_encrypt(payload, aes_key)
    decrypted = ce.aes256gcm_decrypt(envelope, aes_key)

    print("[AES-GCM] target:", payload["target"], "| amt:", decrypted["transaction_data"]["amount"])
    assert decrypted == payload


# ---------- ECDH / HKDF Tests ----------

def test_ecdh_key_exchange_roundtrip():
    priv1, pub1 = ce.generate_ec_keypair()
    priv2, pub2 = ce.generate_ec_keypair()
    k1 = ce.derive_session_key_from_peer(pub2, priv1)
    k2 = ce.derive_session_key_from_peer(pub1, priv2)
    print("[ECDH] keylen:", len(k1))
    assert k1 == k2
    assert len(k1) == 32


# ---------- Downstream Envelope Tests ----------

def test_create_downstream_envelope(ecdsa_keypair, realistic_payload_for_tests):
    _, _, _, pub_pem = ecdsa_keypair
    payload = copy.deepcopy(realistic_payload_for_tests)

    envelope, session_key = ce.create_downstream_envelope(payload["transaction_data"], pub_pem)
    decrypted = ce.aes256gcm_decrypt(envelope, session_key)

    print("[Envelope] eph (trunc):", envelope["ephemeral_pubkey"][:32], "…", "| amt:", decrypted["amount"])
    assert decrypted == payload["transaction_data"]


# ---------- Timestamp Tests ----------

def test_validate_timestamp_valid(realistic_payload_for_tests):
    ts = realistic_payload_for_tests["timestamp"]
    result = ce.validate_timestamp(ts)
    print("[Timestamp] valid?", result)
    assert result is True


def test_validate_timestamp_expired():
    past = int(time.time()) - 9999
    result = ce.validate_timestamp(past, window_seconds=30)
    print("[Timestamp] expired?", result)
    assert result is False


# ---------- Functional / Performance Tests ----------

@pytest.mark.parametrize("size_kb", [64, 512, 2048])
def test_aes256gcm_large_realistic_payload(aes_key, size_kb):
    # Build a realistic middleware payload
    base_payload = {
        "transaction_id": os.urandom(16).hex(),
        "user_id": 12345,
        "amount": 1250.50,
        "currency": "NGN",
        "recipient": {"id": 54321, "account": "0099887766"},
        "metadata": {"tags": ["secure", "payment", "test"], "notes": "Performance test"}
    }
    json_blob = json.dumps(base_payload).encode()
    expected_padding_len = max(0, size_kb * 1024 - len(json_blob))
    padding = os.urandom(expected_padding_len)
    realistic_payload = {
        "envelope": base_payload,
        "padding": base64.b64encode(padding).decode()
    }

    start_enc = time.perf_counter()
    envelope = ce.aes256gcm_encrypt(realistic_payload, aes_key)
    enc_time = time.perf_counter() - start_enc

    start_dec = time.perf_counter()
    decrypted = ce.aes256gcm_decrypt(envelope, aes_key)
    dec_time = time.perf_counter() - start_dec

    # Integrity checks
    assert decrypted["envelope"] == base_payload
    assert len(base64.b64decode(decrypted["padding"])) == expected_padding_len

    print(f"[Functional] AES-GCM | ~{size_kb}KB | enc={enc_time:.4f}s | dec={dec_time:.4f}s")

@pytest.mark.parametrize("iterations", [200, 1000])
def test_ecdsa_sign_verify_performance(iterations):
    """Benchmark ce.ecdsa_sign + ce.ecdsa_verify on a realistic payload using generate_ec_keypair() key."""
    
    # Generate a single EC P-384 key
    priv_key, pub_der = ce.generate_ec_keypair()

    # Serialize private key to PEM for ce.ecdsa_sign
    priv_pem = priv_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()

    # Serialize public key to PEM for ce.ecdsa_verify
    pub_key = priv_key.public_key()
    pub_pem = pub_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()

    payload = {
        "transaction_id": os.urandom(16).hex(),
        "user_id": 12345,
        "amount": 2500.75,
        "currency": "NGN",
        "recipient": {"id": 54321, "account": "0099887766"},
        "timestamp": int(time.time()),
    }

    # ---- Sign benchmark ----
    start_sign = time.perf_counter()
    for _ in range(iterations):
        sig = ce.ecdsa_sign(payload, priv_pem)
    sign_time = time.perf_counter() - start_sign

    # ---- Verify benchmark ----
    start_verify = time.perf_counter()
    for _ in range(iterations):
        assert ce.ecdsa_verify(payload, sig, pub_pem)
    verify_time = time.perf_counter() - start_verify

    print(
        f"[Perf:ECDSA-P384] Iterations={iterations} | "
        f"Sign Time={sign_time:.4f}s | Verify Time={verify_time:.4f}s | "
        f"Avg Sign={(sign_time/iterations*1000):.3f}ms/op | "
        f"Avg Verify={(verify_time/iterations*1000):.3f}ms/op"
    )
