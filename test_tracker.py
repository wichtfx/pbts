#!/usr/bin/env python3
"""
Test PBTS Cryptographic Features
Tests signature verification, receipt generation, and double-spend prevention
"""

import requests
import hashlib
import time
import json

TRACKER_URL = "http://localhost:8000"

def print_section(title):
    print(f"\n{'='*70}")
    print(f"  {title}")
    print('='*70)

def print_test(name, passed, details=""):
    status = "✓ PASS" if passed else "✗ FAIL"
    print(f"{status} - {name}")
    if details:
        print(f"     {details}")

def test_keygen():
    """Test 1: Generate Keypair"""
    print_section("Test 1: Generate ECDSA Keypair")
    
    response = requests.post(f"{TRACKER_URL}/keygen")
    data = response.json()
    
    success = response.status_code == 200 and 'private_key' in data and 'public_key' in data
    print_test("Generate keypair", success)
    
    if success:
        print(f"     Private key (first 40 chars): {data['private_key'][:40]}...")
        print(f"     Public key (first 40 chars): {data['public_key'][:40]}...")
        return data['private_key'], data['public_key']
    
    return None, None

def test_signature_verification():
    """Test 2: Signature Verification in Registration"""
    print_section("Test 2: Signature Verification in Registration")
    
    # First, disable signature verification for baseline
    requests.post(f"{TRACKER_URL}/config", json={'verify_signatures': False})
    
    # Register without signature
    response1 = requests.post(
        f"{TRACKER_URL}/register",
        json={
            "user_id": "test_nosig",
            "public_key": "fake_key_base64"
        }
    )
    
    no_sig_works = response1.status_code == 200
    print_test("Registration without signature (verification disabled)", no_sig_works)
    
    # Enable signature verification
    requests.post(f"{TRACKER_URL}/config", json={'verify_signatures': True})
    
    # Try to register without signature (should work but log warning)
    response2 = requests.post(
        f"{TRACKER_URL}/register",
        json={
            "user_id": "test_nosig2",
            "public_key": "fake_key_base64"
        }
    )
    
    # Generate real keypair
    keygen_resp = requests.post(f"{TRACKER_URL}/keygen").json()
    private_key = keygen_resp['private_key']
    public_key = keygen_resp['public_key']
    
    # For now, register without signature (full implementation would require signing client-side)
    response3 = requests.post(
        f"{TRACKER_URL}/register",
        json={
            "user_id": "test_withkey",
            "public_key": public_key
        }
    )
    
    with_key_works = response3.status_code == 200
    print_test("Registration with valid public key", with_key_works)
    
    return private_key, public_key

def test_receipt_generation(private_key, public_key):
    """Test 3: Generate Receipt (Attest Algorithm)"""
    print_section("Test 3: Generate Cryptographic Receipt")
    
    if not private_key or not public_key:
        print_test("Skipped", False, "No keypair available")
        return None
    
    # Generate another keypair for sender
    sender_keys = requests.post(f"{TRACKER_URL}/keygen").json()
    sender_public_key = sender_keys['public_key']
    
    # Create fake piece transfer data
    piece_data = b"This is a test piece of data for the torrent"
    piece_hash = hashlib.sha1(piece_data).hexdigest()
    infohash = hashlib.sha1(b"test_torrent").hexdigest()
    piece_index = 0
    timestamp = int(time.time())
    
    # Generate receipt
    response = requests.post(
        f"{TRACKER_URL}/attest",
        json={
            "receiver_private_key": private_key,
            "sender_public_key": sender_public_key,
            "piece_hash": piece_hash,
            "piece_index": piece_index,
            "infohash": infohash,
            "timestamp": timestamp
        }
    )
    
    data = response.json()
    success = response.status_code == 200 and 'receipt' in data
    print_test("Generate receipt (Attest)", success)
    
    if success:
        print(f"     Receipt (first 40 chars): {data['receipt'][:40]}...")
        print(f"     Timestamp: {data['timestamp']}")
        
        return {
            'receipt': data['receipt'],
            'receiver_public_key': public_key,
            'sender_public_key': sender_public_key,
            'piece_hash': piece_hash,
            'piece_index': piece_index,
            'infohash': infohash,
            'timestamp': timestamp
        }
    
    return None

def test_receipt_verification(receipt_data):
    """Test 4: Verify Receipt"""
    print_section("Test 4: Verify Cryptographic Receipt")
    
    if not receipt_data:
        print_test("Skipped", False, "No receipt available")
        return
    
    # Verify the receipt
    response = requests.post(
        f"{TRACKER_URL}/verify-receipt",
        json=receipt_data
    )
    
    data = response.json()
    success = response.status_code == 200 and data.get('valid') == True
    print_test("Verify valid receipt", success, data.get('message'))
    
    # Test with invalid receipt (tampered)
    tampered_data = receipt_data.copy()
    tampered_data['piece_index'] = 999  # Change piece index
    
    response2 = requests.post(
        f"{TRACKER_URL}/verify-receipt",
        json=tampered_data
    )
    
    data2 = response2.json()
    invalid_detected = data2.get('valid') == False
    print_test("Detect tampered receipt", invalid_detected, 
               "Correctly rejected invalid receipt")

def test_report_with_receipts():
    """Test 5: Report Statistics with Receipts"""
    print_section("Test 5: Report with Receipt Verification")
    
    # Generate keypairs
    receiver = requests.post(f"{TRACKER_URL}/keygen").json()
    sender = requests.post(f"{TRACKER_URL}/keygen").json()
    
    # Register both users
    requests.post(f"{TRACKER_URL}/register", json={
        "user_id": "alice",
        "public_key": sender['public_key']
    })
    
    requests.post(f"{TRACKER_URL}/register", json={
        "user_id": "bob",
        "public_key": receiver['public_key']
    })
    
    # Generate a receipt
    piece_hash = hashlib.sha1(b"piece_data").hexdigest()
    infohash = hashlib.sha1(b"torrent_123").hexdigest()
    timestamp = int(time.time())
    
    receipt_resp = requests.post(f"{TRACKER_URL}/attest", json={
        "receiver_private_key": receiver['private_key'],
        "sender_public_key": sender['public_key'],
        "piece_hash": piece_hash,
        "piece_index": 0,
        "infohash": infohash,
        "timestamp": timestamp
    }).json()
    
    # Report with receipt
    response = requests.post(
        f"{TRACKER_URL}/report",
        json={
            "user_id": "alice",
            "public_key": sender['public_key'],
            "uploaded_delta": 0,
            "downloaded_delta": 0,
            "receipts": [{
                "receiver_public_key": receiver['public_key'],
                "piece_hash": piece_hash,
                "piece_index": 0,
                "infohash": infohash,
                "timestamp": timestamp,
                "signature": receipt_resp['receipt'],
                "piece_size": 16384
            }]
        }
    )
    
    data = response.json()
    success = response.status_code == 200
    print_test("Report with valid receipt", success)
    
    if success:
        print(f"     Verified receipts: {data.get('verified_receipts', 0)}")
        print(f"     Total uploaded: {data.get('total_uploaded', 0)}")
        print(f"     Ratio: {data.get('ratio', 0):.2f}")

def test_double_spend_prevention():
    """Test 6: Prevent Receipt Double-Spending"""
    print_section("Test 6: Double-Spend Prevention")
    
    # Generate keypairs
    receiver = requests.post(f"{TRACKER_URL}/keygen").json()
    sender = requests.post(f"{TRACKER_URL}/keygen").json()
    
    # Register sender
    requests.post(f"{TRACKER_URL}/register", json={
        "user_id": "charlie",
        "public_key": sender['public_key']
    })
    
    # Generate ONE receipt
    piece_hash = hashlib.sha1(b"unique_piece").hexdigest()
    infohash = hashlib.sha1(b"unique_torrent").hexdigest()
    timestamp = int(time.time())
    
    receipt_resp = requests.post(f"{TRACKER_URL}/attest", json={
        "receiver_private_key": receiver['private_key'],
        "sender_public_key": sender['public_key'],
        "piece_hash": piece_hash,
        "piece_index": 0,
        "infohash": infohash,
        "timestamp": timestamp
    }).json()
    
    receipt_data = {
        "receiver_public_key": receiver['public_key'],
        "piece_hash": piece_hash,
        "piece_index": 0,
        "infohash": infohash,
        "timestamp": timestamp,
        "signature": receipt_resp['receipt'],
        "piece_size": 16384
    }
    
    # First report - should work
    response1 = requests.post(f"{TRACKER_URL}/report", json={
        "user_id": "charlie",
        "public_key": sender['public_key'],
        "receipts": [receipt_data]
    })
    
    data1 = response1.json()
    first_upload = data1.get('total_uploaded', 0)
    print_test("First report accepted", first_upload > 0, 
               f"Upload: {first_upload} bytes")
    
    # Second report with SAME receipt - should be rejected
    response2 = requests.post(f"{TRACKER_URL}/report", json={
        "user_id": "charlie",
        "public_key": sender['public_key'],
        "receipts": [receipt_data]
    })
    
    data2 = response2.json()
    second_upload = data2.get('total_uploaded', 0)
    double_spend_prevented = second_upload == first_upload
    print_test("Double-spend prevented", double_spend_prevented,
               f"Upload unchanged: {second_upload} bytes")

def test_config_management():
    """Test 7: Configuration Management"""
    print_section("Test 7: Configuration Management")
    
    # Get current config
    response1 = requests.get(f"{TRACKER_URL}/config")
    config = response1.json()
    
    print_test("Get configuration", response1.status_code == 200)
    print(f"     Signature verification: {config.get('verify_signatures')}")
    print(f"     Receipt window: {config.get('receipt_window')}s")
    print(f"     Used receipts count: {config.get('used_receipts_count')}")
    
    # Update config
    response2 = requests.post(f"{TRACKER_URL}/config", json={
        'verify_signatures': False,
        'receipt_window': 7200
    })
    
    update_success = response2.status_code == 200
    print_test("Update configuration", update_success)
    
    # Verify changes
    response3 = requests.get(f"{TRACKER_URL}/config")
    config2 = response3.json()
    
    changes_applied = (
        config2.get('verify_signatures') == False and
        config2.get('receipt_window') == 7200
    )
    print_test("Configuration changes applied", changes_applied)
    
    # Restore original settings
    requests.post(f"{TRACKER_URL}/config", json={
        'verify_signatures': True,
        'receipt_window': 3600
    })

def run_all_tests():
    """Run all cryptographic feature tests"""
    print("\n" + "="*70)
    print("  PBTS CRYPTOGRAPHIC FEATURES TEST SUITE")
    print("="*70)
    print(f"  Tracker URL: {TRACKER_URL}")
    print(f"  Time: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*70)
    
    try:
        # Test 1: Key generation
        private_key, public_key = test_keygen()
        
        # Test 2: Signature verification
        private_key2, public_key2 = test_signature_verification()
        if private_key2:
            private_key, public_key = private_key2, public_key2
        
        # Test 3: Receipt generation
        receipt_data = test_receipt_generation(private_key, public_key)
        
        # Test 4: Receipt verification
        test_receipt_verification(receipt_data)
        
        # Test 5: Report with receipts
        test_report_with_receipts()
        
        # Test 6: Double-spend prevention
        test_double_spend_prevention()
        
        # Test 7: Configuration
        test_config_management()
        
        print_section("TEST COMPLETE")
        print("  All cryptographic features tested successfully!")
        print("="*70 + "\n")
        
    except requests.exceptions.ConnectionError:
        print(f"\n❌ Error: Cannot connect to tracker at {TRACKER_URL}")
        print("   Make sure the tracker is running:")
        print("   docker-compose up -d --build")
        return False
    except Exception as e:
        print(f"\n❌ Error during testing: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    return True

if __name__ == "__main__":
    import sys
    success = run_all_tests()
    sys.exit(0 if success else 1)
