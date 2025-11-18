#!/usr/bin/env python3
"""
Test suite for PBTS Smart Contract Integration
Tests all contract endpoints and functionality
"""

import unittest
import requests
import json
import hashlib
import time
import os
import subprocess
import re
from dotenv import load_dotenv, set_key, find_dotenv

# Load environment variables
load_dotenv()

BASE_URL = "http://localhost:8000"
ENV_FILE = find_dotenv() or "smartcontract/.env"


class TestSmartContractIntegration(unittest.TestCase):
    """Test smart contract integration endpoints"""
    
    @classmethod
    def setUpClass(cls):
        """Set up test environment - deploy factory if needed"""
        print("\n" + "="*60)
        print("Setting up Smart Contract Tests")
        print("="*60)
        
        # Check if tracker is running
        try:
            response = requests.get(f"{BASE_URL}/health", timeout=2)
            if response.status_code != 200:
                raise Exception("Tracker not responding")
        except Exception as e:
            print(f"\nERROR: Tracker is not running at {BASE_URL}")
            print("Please start the tracker first: python tracker.py")
            raise unittest.SkipTest("Tracker not running")
        
        # Check contract status
        status = requests.get(f"{BASE_URL}/contract/status").json()
        print(f"\n Current Contract Status:")
        print(f"   - Configured: {status.get('configured')}")
        print(f"   - Connected to RPC: {status.get('connected')}")
        print(f"   - Factory: {status.get('factory_address') or 'Not deployed'}")
        print(f"   - Reputation: {status.get('reputation_address') or 'Not initialized'}")
        
        # Deploy factory if not exists
        if not status.get('factory_address'):
            print("\n Deploying new ReputationFactory...")
            cls.deploy_factory()
            # Wait for tracker to reload
            time.sleep(1)
        
        # Initialize reputation contract for tests
        if not status.get('reputation_address'):
            print("\n Initializing Reputation contract...")
            response = requests.post(f"{BASE_URL}/contract/init")
            result = response.json()
            if result.get('success'):
                print(f"   OK Reputation contract created: {result['reputation_address']}")
                cls.reputation_address = result['reputation_address']
            else:
                raise Exception(f"Failed to initialize contract: {result.get('error')}")
        else:
            cls.reputation_address = status.get('reputation_address')
        
        print("\nSUCCESS: Setup complete!\n")
    
    @classmethod
    def deploy_factory(cls):
        """Deploy a new ReputationFactory contract"""
        try:
            # Load environment
            rpc = os.getenv('RPC', 'http://127.0.0.1:8545')
            pk0 = os.getenv('PK0')
            
            if not pk0:
                raise Exception("PK0 not set in environment")
            
            print(f"   - RPC: {rpc}")
            print(f"   - Deploying with account: {os.getenv('A0', 'unknown')}")
            
            # Change to smartcontract directory and deploy
            result = subprocess.run(
                [
                    'forge', 'create', 'src/factory.sol:ReputationFactory',
                    '--rpc-url', rpc,
                    '--private-key', pk0
                ],
                cwd='smartcontract',
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode != 0:
                print(f"   ERROR: Deploy failed: {result.stderr}")
                raise Exception(f"Factory deployment failed: {result.stderr}")
            
            # Extract deployed address from forge output
            output = result.stdout + result.stderr
            factory_address = None
            
            # Look for "Deployed to:" line
            match = re.search(r'Deployed to:\s*(0x[a-fA-F0-9]{40})', output, re.IGNORECASE)
            if match:
                factory_address = match.group(1)
            
            # Try alternative patterns if first one fails
            if not factory_address:
                match = re.search(r'Contract Address:\s*(0x[a-fA-F0-9]{40})', output, re.IGNORECASE)
                if match:
                    factory_address = match.group(1)
            
            if not factory_address:
                match = re.search(r'contractAddress["\s:]+([0x[a-fA-F0-9]{40}])', output, re.IGNORECASE)
                if match:
                    factory_address = match.group(1)
            
            if not factory_address:
                print(f"   Deployment output: {output}")
                raise Exception("Could not extract deployed contract address from output")
            
            print(f"   OK Factory deployed: {factory_address}")
            
            # Reload environment in current process
            os.environ['FACTORY'] = factory_address
            
            return factory_address
            
        except subprocess.TimeoutExpired:
            raise Exception("Factory deployment timed out")
        except json.JSONDecodeError as e:
            raise Exception(f"Failed to parse deployment output: {e}")
        except Exception as e:
            raise Exception(f"Factory deployment error: {e}")
    
    def test_01_contract_status(self):
        """Test contract status endpoint"""
        print("\n Test 1: Contract Status")
        response = requests.get(f"{BASE_URL}/contract/status")
        self.assertEqual(response.status_code, 200)
        
        data = response.json()
        print(f"   Status: {json.dumps(data, indent=2)}")
        
        self.assertTrue(data['configured'], "Contract should be configured")
        self.assertTrue(data['connected'], "Should be connected to RPC")
        self.assertIsNotNone(data['factory_address'], "Factory should be deployed")
        print("   OK Contract is properly configured")
    
    def test_02_init_new_contract(self):
        """Test initializing a new Reputation contract"""
        print("\n Test 2: Initialize New Reputation Contract")
        
        response = requests.post(f"{BASE_URL}/contract/init")
        self.assertEqual(response.status_code, 200)
        
        data = response.json()
        print(f"   Response: {json.dumps(data, indent=2)}")
        
        self.assertTrue(data['success'], "Initialization should succeed")
        self.assertIsNotNone(data['reputation_address'], "Should return new contract address")
        self.assertEqual(
            data['referrer_address'], 
            '0x0000000000000000000000000000000000000000',
            "Default referrer should be zero address"
        )
        
        # Update class variable for other tests
        self.__class__.reputation_address = data['reputation_address']
        
        print(f"   OK New contract created: {data['reputation_address']}")
    
    def test_03_register_user(self):
        """Test registering a user on smart contract"""
        print("\n Test 3: Register User")
        
        # Generate password hash
        password = "test_password_123"
        password_hash = "0x" + hashlib.sha256(password.encode()).hexdigest()
        
        user_data = {
            "username": "test_user_1",
            "salt": "random_salt_abc123",
            "password_hash": password_hash,
            "download_size": 0,
            "upload_size": 0
        }
        
        print(f"   Registering: {user_data['username']}")
        
        response = requests.post(
            f"{BASE_URL}/contract/register",
            json=user_data
        )
        self.assertEqual(response.status_code, 200)
        
        data = response.json()
        print(f"   Response: {json.dumps(data, indent=2)}")
        
        self.assertTrue(data['success'], "Registration should succeed")
        self.assertIn('tx_hash', data, "Should return transaction hash")
        print(f"   OK User registered successfully (TX: {data['tx_hash'][:10]}...)")
    
    def test_04_get_user(self):
        """Test retrieving user data from smart contract"""
        print("\n Test 4: Get User Data")
        
        username = "test_user_1"
        response = requests.get(f"{BASE_URL}/contract/user/{username}")
        self.assertEqual(response.status_code, 200)
        
        data = response.json()
        print(f"   Response: {json.dumps(data, indent=2)}")
        
        self.assertTrue(data['success'], "Get user should succeed")
        self.assertIn('user', data, "Should return user data")
        
        user = data['user']
        self.assertEqual(user['username'], username, "Username should match")
        self.assertIn('passwordHash', user, "Should have password hash")
        self.assertIn('salt', user, "Should have salt")
        self.assertEqual(user['downloadSize'], 0, "Initial download should be 0")
        self.assertEqual(user['uploadSize'], 0, "Initial upload should be 0")
        
        print(f"   OK User data retrieved successfully")
        print(f"   - Username: {user['username']}")
        print(f"   - Salt: {user['salt']}")
        print(f"   - Download: {user['downloadSize']} bytes")
        print(f"   - Upload: {user['uploadSize']} bytes")
    
    def test_05_update_user_stats(self):
        """Test updating user statistics on smart contract"""
        print("\n Test 5: Update User Statistics")
        
        update_data = {
            "username": "test_user_1",
            "download_size": 1024000,  # 1 MB
            "upload_size": 2048000     # 2 MB
        }
        
        print(f"   Updating stats: {update_data['download_size']} down, {update_data['upload_size']} up")
        
        response = requests.post(
            f"{BASE_URL}/contract/update",
            json=update_data
        )
        self.assertEqual(response.status_code, 200)
        
        data = response.json()
        print(f"   Response: {json.dumps(data, indent=2)}")
        
        self.assertTrue(data['success'], "Update should succeed")
        self.assertIn('tx_hash', data, "Should return transaction hash")
        
        # Verify the update by getting user data
        response = requests.get(f"{BASE_URL}/contract/user/test_user_1")
        user_data = response.json()['user']
        
        self.assertEqual(user_data['downloadSize'], 1024000, "Download size should be updated")
        self.assertEqual(user_data['uploadSize'], 2048000, "Upload size should be updated")
        self.assertEqual(user_data['ratio'], 2.0, "Ratio should be 2.0")
        
        print(f"   OK User stats updated successfully")
        print(f"   - New ratio: {user_data['ratio']}")
    
    def test_06_register_multiple_users(self):
        """Test registering multiple users"""
        print("\n Test 6: Register Multiple Users")
        
        users = [
            {"username": "alice", "upload": 5000000, "download": 2500000},
            {"username": "bob", "upload": 1000000, "download": 3000000},
            {"username": "charlie", "upload": 10000000, "download": 5000000}
        ]
        
        for user_info in users:
            # Register user
            password_hash = "0x" + hashlib.sha256(user_info['username'].encode()).hexdigest()
            
            response = requests.post(
                f"{BASE_URL}/contract/register",
                json={
                    "username": user_info['username'],
                    "salt": f"salt_{user_info['username']}",
                    "password_hash": password_hash,
                    "download_size": user_info['download'],
                    "upload_size": user_info['upload']
                }
            )
            
            data = response.json()
            self.assertTrue(data['success'], f"Should register {user_info['username']}")
            print(f"   OK Registered {user_info['username']} (ratio: {user_info['upload']/user_info['download']:.2f})")
        
        print(f"   OK All {len(users)} users registered successfully")
    
    def test_07_get_all_registered_users(self):
        """Test retrieving all registered users"""
        print("\n Test 7: Retrieve All Registered Users")
        
        usernames = ["test_user_1", "alice", "bob", "charlie"]
        
        for username in usernames:
            response = requests.get(f"{BASE_URL}/contract/user/{username}")
            self.assertEqual(response.status_code, 200)
            
            data = response.json()
            self.assertTrue(data['success'], f"Should get {username}")
            
            user = data['user']
            print(f"   - {username}: {user['uploadSize']} up / {user['downloadSize']} down = ratio {user['ratio']:.2f}")
        
        print(f"   OK Retrieved all {len(usernames)} users")
    
    def test_08_update_existing_user(self):
        """Test updating an existing user's stats"""
        print("\n Test 8: Update Existing User")
        
        # Update alice's stats
        response = requests.post(
            f"{BASE_URL}/contract/update",
            json={
                "username": "alice",
                "download_size": 5000000,
                "upload_size": 10000000
            }
        )
        
        data = response.json()
        self.assertTrue(data['success'], "Update should succeed")
        
        # Verify
        response = requests.get(f"{BASE_URL}/contract/user/alice")
        user = response.json()['user']
        
        self.assertEqual(user['uploadSize'], 10000000)
        self.assertEqual(user['downloadSize'], 5000000)
        
        print(f"   OK Updated alice: ratio changed to {user['ratio']:.2f}")
    
    def test_09_nonexistent_user(self):
        """Test getting a non-existent user"""
        print("\n Test 9: Get Non-existent User")
        
        response = requests.get(f"{BASE_URL}/contract/user/nonexistent_user")
        data = response.json()
        
        # User should exist but have empty data (passwordHash = 0x0...0)
        user = data['user']
        print(f"   User data: {json.dumps(user, indent=2)}")
        
        # Check if user doesn't exist (all zeros)
        is_empty = user['passwordHash'] == '0x' + '0' * 64
        print(f"   OK Non-existent user returns empty data: {is_empty}")
    
    def test_10_init_with_referrer(self):
        """Test initializing contract with a referrer"""
        print("\n Test 10: Initialize Contract with Referrer")
        
        # Use current reputation as referrer
        referrer = self.reputation_address
        
        response = requests.post(
            f"{BASE_URL}/contract/init",
            json={"referrer_address": referrer}
        )
        
        data = response.json()
        print(f"   Response: {json.dumps(data, indent=2)}")
        
        self.assertTrue(data['success'], "Initialization should succeed")
        self.assertEqual(data['referrer_address'], referrer, "Referrer should match")
        
        print(f"   OK New contract created with referrer: {referrer[:10]}...")
        print(f"   OK New contract address: {data['reputation_address'][:10]}...")


def run_tests():
    """Run all tests with detailed output"""
    # Create test suite
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromTestCase(TestSmartContractIntegration)
    
    # Run with verbose output
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Print summary
    print("\n" + "="*60)
    print("TEST SUMMARY")
    print("="*60)
    print(f"Tests run: {result.testsRun}")
    print(f"Successes: {result.testsRun - len(result.failures) - len(result.errors)}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    
    if result.wasSuccessful():
        print("\nSUCCESS: All tests passed!")
    else:
        print("\nERROR: Some tests failed")
    
    return result.wasSuccessful()


if __name__ == '__main__':
    success = run_tests()
    exit(0 if success else 1)

