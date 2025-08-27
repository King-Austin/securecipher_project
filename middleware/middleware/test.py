import base64
import json
import os
import time
import pytest
import statistics
import multiprocessing as mp
from datetime import datetime

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

from modules import crypto_engine as ce

# Test configuration
STRESS_TEST_ITERATIONS = 100
CONCURRENT_WORKERS = 4

@pytest.fixture
def keypair():
    """Generate ECDSA/ECDH keypair (PEM private, PEM public)."""
    priv = ec.generate_private_key(ce.ECDH_CURVE)
    pub = priv.public_key()
    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode()
    pub_pem = pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    return priv, priv_pem, pub_pem

def test_hash_data():
    """Test hash_data function with different input types"""
    # Test with string
    result1 = ce.hash_data("hello world")
    assert len(result1) == 64
    
    # Test with bytes
    result2 = ce.hash_data(b"hello world")
    assert result1 == result2
    
    # Test with dict
    data_dict = {"message": "hello", "number": 42}
    result3 = ce.hash_data(data_dict)
    assert len(result3) == 64

def test_ecdsa_sign_and_verify(keypair):
    """Test ECDSA signing and verification"""
    priv, priv_pem, pub_pem = keypair
    payload = {"msg": "hello", "n": 42}
    
    sig = ce.ecdsa_sign(payload, priv_pem)
    assert ce.ecdsa_verify(payload, sig, pub_pem)

    # Test verification fails with tampered payload
    tampered = {"msg": "bye", "n": 42}
    assert not ce.ecdsa_verify(tampered, sig, pub_pem)

@pytest.mark.performance
def test_ecdsa_performance(keypair):
    """Performance test for ECDSA operations"""
    _, priv_pem, pub_pem = keypair
    payload = {"test": "performance", "counter": 0}
    
    sign_times = []
    verify_times = []
    
    for i in range(STRESS_TEST_ITERATIONS):
        payload["counter"] = i
        
        # Signing
        sign_start = time.perf_counter()
        sig = ce.ecdsa_sign(payload, priv_pem)
        sign_times.append(time.perf_counter() - sign_start)
        
        # Verification
        verify_start = time.perf_counter()
        result = ce.ecdsa_verify(payload, sig, pub_pem)
        verify_times.append(time.perf_counter() - verify_start)
        
        assert result
    
    # Assert performance thresholds (adjust based on your requirements)
    avg_sign = statistics.mean(sign_times) * 1000
    avg_verify = statistics.mean(verify_times) * 1000
    
    assert avg_sign < 100, f"ECDSA signing too slow: {avg_sign:.3f}ms"
    assert avg_verify < 100, f"ECDSA verification too slow: {avg_verify:.3f}ms"

@pytest.mark.performance
def test_aes256gcm_performance():
    """Performance test for AES-GCM operations"""
    encrypt_times = []
    decrypt_times = []
    key = os.urandom(32)
    
    for i in range(STRESS_TEST_ITERATIONS):
        payload = {"data": f"test_{i}", "value": i}
        
        # Encryption
        encrypt_start = time.perf_counter()
        envelope = ce.aes256gcm_encrypt(payload, key)
        encrypt_times.append(time.perf_counter() - encrypt_start)
        
        # Decryption
        decrypt_start = time.perf_counter()
        recovered = ce.aes256gcm_decrypt(envelope, key)
        decrypt_times.append(time.perf_counter() - decrypt_start)
        
        assert recovered == payload
    
    # Assert performance thresholds
    avg_encrypt = statistics.mean(encrypt_times) * 1000
    avg_decrypt = statistics.mean(decrypt_times) * 1000
    
    assert avg_encrypt < 50, f"AES encryption too slow: {avg_encrypt:.3f}ms"
    assert avg_decrypt < 50, f"AES decryption too slow: {avg_decrypt:.3f}ms"

@pytest.mark.stress
def test_concurrent_performance():
    """Concurrent stress test"""
    def worker(task_id, results):
        key = os.urandom(32)
        operations = 0
        start = time.perf_counter()
        
        for i in range(STRESS_TEST_ITERATIONS // CONCURRENT_WORKERS):
            payload = {"task": task_id, "iteration": i}
            envelope = ce.aes256gcm_encrypt(payload, key)
            recovered = ce.aes256gcm_decrypt(envelope, key)
            assert recovered == payload
            operations += 2
        
        duration = time.perf_counter() - start
        results.put((operations, duration))
    
    results = mp.Queue()
    processes = []
    
    for i in range(CONCURRENT_WORKERS):
        p = mp.Process(target=worker, args=(i, results))
        processes.append(p)
        p.start()
    
    for p in processes:
        p.join()
    
    total_operations = 0
    max_duration = 0
    
    while not results.empty():
        operations, duration = results.get()
        total_operations += operations
        max_duration = max(max_duration, duration)
    
    throughput = total_operations / max_duration
    assert throughput > 100, f"Throughput too low: {throughput:.2f} ops/sec"

# Run with: pytest -v -m "performance or stress" --tb=short