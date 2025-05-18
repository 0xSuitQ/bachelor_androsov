# test_keyshares_contract.py
import pytest
import json
import random
import os
from web3 import Web3
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Contract information
CONTRACT_ADDRESS = Web3.to_checksum_address("0x6b017cbf9ffbdd70e2b8a78ef06c163ab722784c")
PRIVATE_KEY = os.getenv("PRIVATE_KEY")

@pytest.fixture(scope="session")
def web3():
	"""Setup Web3 connection"""
	return Web3(Web3.HTTPProvider('https://polygon-amoy.publicnode.com'))

@pytest.fixture(scope="session")
def account(web3):
	"""Setup account from private key"""
	print(web3.eth.account.from_key(PRIVATE_KEY))
	return web3.eth.account.from_key(PRIVATE_KEY)

@pytest.fixture(scope="session")
def contract(web3):
	"""Setup contract instance"""
	# Load ABI from file (or directly include it here)
	with open('contract_abi.json', 'r') as f:
		contract_abi = json.load(f)
	
	return web3.eth.contract(address=CONTRACT_ADDRESS, abi=contract_abi)

@pytest.fixture(scope="session")
def test_username():
	"""Generate a unique test username for each test run"""
	return f"test_user_{random.randint(1000, 9999)}"

@pytest.fixture(scope="session")
def test_shares():
	"""Generate test share data"""
	return [
		json.dumps([["1", "123456", "0", "30"], ["2", "789012", "0", "30"]]),
		json.dumps([["1", "901234", "1", "30"], ["2", "567890", "1", "30"]])
	]

@pytest.fixture(scope="session")
def stored_test_user(web3, contract, account, test_username, test_shares):
	"""Fixture that creates a test user and cleans up after test"""
	estimated_gas = contract.functions.storeKeyShares(
		test_username, 2, 60, test_shares
	).estimate_gas({'from': account.address})
	gas_limit = int(estimated_gas * 1.1)  # Add 10% buffer

	store_tx = contract.functions.storeKeyShares(
		test_username, 2, 60, test_shares
	).build_transaction({
		'from': account.address,
		'nonce': web3.eth.get_transaction_count(account.address),
		'gas': gas_limit,  # Use estimated gas
		'gasPrice': web3.eth.gas_price
	})
	
	signed_tx = account.sign_transaction(store_tx)
	tx_hash = web3.eth.send_raw_transaction(signed_tx.raw_transaction)
	receipt = web3.eth.wait_for_transaction_receipt(tx_hash)
	
	# Return the test data for use in tests
	yield {
		'username': test_username,
		'shares': test_shares,
		'chunks': 2,
		'total_length': 60
	}
	
	# # Teardown: Delete the test user after the test
	# try:
	#     delete_tx = contract.functions.deleteUser(test_username).build_transaction({
	#         'from': account.address,
	#         'nonce': web3.eth.get_transaction_count(account.address),
	#         'gas': 500000,
	#         'gasPrice': web3.eth.gas_price
	#     })
		
	#     signed_delete_tx = account.sign_transaction(delete_tx)
	#     delete_tx_hash = web3.eth.send_raw_transaction(signed_delete_tx.raw_transaction)
	#     web3.eth.wait_for_transaction_receipt(delete_tx_hash)
	# except Exception as e:
	#     print(f"Failed to delete test user {test_username}: {e}")


# class TestKeySharesManager:
# 	def test_emergency_call(self, web3, contract, account):
# 		"""Try multiple methods to call the contract"""
# 		# Print info
# 		print(f"Contract address: {contract.address}")
# 		print(f"Account address: {account.address}")
		
# 		# Try direct transaction
# 		try:
# 			tx = {
# 				'to': contract.address,
# 				'from': account.address,
# 				'gas': 100000,
# 				'gasPrice': web3.eth.gas_price,
# 				'nonce': web3.eth.get_transaction_count(account.address),
# 				'data': contract.encodeABI(fn_name="userExists", args=["test"])
# 			}
# 			signed = account.sign_transaction(tx)
# 			tx_hash = web3.eth.send_raw_transaction(signed.raw_transaction)
# 			receipt = web3.eth.wait_for_transaction_receipt(tx_hash)
# 			print(f"Direct transaction status: {receipt.status}")
# 		except Exception as e:
# 			print(f"Direct transaction error: {e}")
	
	# def test_store_key_shares(self, web3, contract, account, test_username, test_shares):
	# 	"""Test storing key shares for a new user"""
	# 	# Arrange
	# 	chunks = 2
	# 	total_length = 60
		
	# 	estimated_gas = contract.functions.storeKeyShares(
	# 		test_username, chunks, total_length, test_shares
	# 	).estimate_gas({'from': account.address})

	# 	# Add a small buffer (e.g., 10%)
	# 	gas_limit = int(estimated_gas * 1.1)
	# 	print("gas limit", gas_limit)
	# 	# Use in transaction
	# 	store_tx = contract.functions.storeKeyShares(
	# 		test_username, chunks, total_length, test_shares
	# 	).build_transaction({
	# 		'from': account.address,
	# 		'nonce': web3.eth.get_transaction_count(account.address),
	# 		'gas': gas_limit,
	# 		'gasPrice': web3.eth.gas_price
	# 	})
		
	# 	signed_tx = account.sign_transaction(store_tx)
	# 	tx_hash = web3.eth.send_raw_transaction(signed_tx.raw_transaction)
	# 	receipt = web3.eth.wait_for_transaction_receipt(tx_hash)
		
	# 	# Assert
	# 	assert receipt.status == 1, "Transaction failed"
		
	# 	# Verify the user exists after storing
	# 	exists = contract.functions.userExists(test_username).call({'from': account.address})
	# 	assert exists is True, "User should exist after storing key shares"
		
	# 	# Clean up
	# 	delete_tx = contract.functions.deleteUser(test_username).build_transaction({
	# 		'from': account.address,
	# 		'nonce': web3.eth.get_transaction_count(account.address),
	# 		'gas': 500000,
	# 		'gasPrice': web3.eth.gas_price
	# 	})
		
	# 	signed_delete_tx = account.sign_transaction(delete_tx)
	# 	delete_tx_hash = web3.eth.send_raw_transaction(signed_delete_tx.raw_transaction)
	# 	web3.eth.wait_for_transaction_receipt(delete_tx_hash)
	
	# def test_user_exists(self, contract, stored_test_user, account):
	# 	"""Test checking if a user exists"""
	# 	# Arrange
	# 	username = stored_test_user['username']

	# 	# Act
	# 	exists = contract.functions.userExists(username).call({'from': account.address})
		
	# 	# Assert
	# 	assert exists is True, f"User {username} should exist"
		
	# 	# Also check a non-existent user
	# 	fake_user = f"fake_user_{random.randint(10000, 99999)}"
	# 	fake_exists = contract.functions.userExists(fake_user).call({'from': account.address})
	# 	assert fake_exists is False, f"User {fake_user} should not exist"
	
	# def test_retrieve_key_shares(self, contract, stored_test_user, account):
	# 	"""Test retrieving key shares for a user"""
	# 	# Arrange
	# 	username = stored_test_user['username']
	# 	expected_chunks = stored_test_user['chunks']
	# 	expected_total_length = stored_test_user['total_length']
	# 	expected_shares = stored_test_user['shares']
		
	# 	# Act
	# 	result = contract.functions.retrieveKeyShares(username).call({'from': account.address})
		
	# 	# Assert
	# 	chunks, total_length, shares = result
	# 	assert chunks == expected_chunks, f"Expected {expected_chunks} chunks, got {chunks}"
	# 	assert total_length == expected_total_length, f"Expected total length {expected_total_length}, got {total_length}"
	# 	assert len(shares) == expected_chunks, f"Expected {expected_chunks} share entries, got {len(shares)}"
		
	# 	# Check share content matches
	# 	for i, share in enumerate(shares):
	# 		assert share == expected_shares[i], f"Share at index {i} doesn't match expected value"
	
#     def test_delete_user(self, web3, contract, account, stored_test_user):
#         """Test deleting a user"""
#         # Arrange
#         username = stored_test_user['username']
		
#         # Verify user exists first
#         exists_before = contract.functions.userExists(username).call({'from': account.address})
#         assert exists_before is True, f"User {username} should exist before deletion"
		
#         # Act
#         delete_tx = contract.functions.deleteUser(username).build_transaction({
#             'from': account.address,
#             'nonce': web3.eth.get_transaction_count(account.address),
#             'gas': 500000,
#             'gasPrice': web3.eth.gas_price
#         })
		
#         signed_delete_tx = account.sign_transaction(delete_tx)
#         delete_tx_hash = web3.eth.send_raw_transaction(signed_delete_tx.raw_transaction)
#         receipt = web3.eth.wait_for_transaction_receipt(delete_tx_hash)
		
#         # Assert
#         assert receipt.status == 1, "Delete transaction failed"
		
#         # Verify user no longer exists
#         exists_after = contract.functions.userExists(username).call({'from': account.address})
#         assert exists_after is False, f"User {username} should not exist after deletion"
	
# def test_unauthorized_access(self, web3, contract, account, test_username, test_shares, stored_test_user):
#     """Test that only the server can modify data or read shares"""
#     # Create an account that's not the server
#     unauthorized_key = Web3.eth.account.create().key.hex()
#     unauthorized_account = web3.eth.account.from_key(unauthorized_key)
	
#     # Test 1: Verify unauthorized accounts can't write data
#     with pytest.raises(Exception) as excinfo:
#         store_tx = contract.functions.storeKeyShares(
#             test_username,
#             2,
#             60,
#             test_shares
#         ).call({"from": unauthorized_account.address})
	
#     # Test 2: Verify unauthorized accounts can't read shares
#     username = stored_test_user['username']  # Use a user that exists
	
#     with pytest.raises(Exception) as excinfo:
#         # Try to retrieve shares as unauthorized user
#         shares = contract.functions.retrieveKeyShares(username).call(
#             {"from": unauthorized_account.address}
#         )
	
#     # Test 3: Verify unauthorized accounts can't check if users exist
#     with pytest.raises(Exception) as excinfo:
#         exists = contract.functions.userExists(username).call(
#             {"from": unauthorized_account.address}
#         )
	
#     # Test 4: Verify unauthorized accounts can't delete users
#     with pytest.raises(Exception) as excinfo:
#         delete_tx = contract.functions.deleteUser(username).call(
#             {"from": unauthorized_account.address}
#         )



def test_nikita_key_shares(web3, contract, account):
    """Test retrieving and validating key shares for user 'nikita'"""
    # Constants
    username = "nikita"
    
    # 1. Check if user exists
    exists = contract.functions.userExists(username).call({'from': account.address})
    print(f"User '{username}' exists: {exists}")
    
    if not exists:
        pytest.skip(f"User '{username}' doesn't exist in the contract")
    
    # 2. Retrieve key shares
    result = contract.functions.retrieveKeyShares(username).call({'from': account.address})
    chunks, total_length, shares = result
    
    # 3. Print detailed information
    print(f"\n===== KEY SHARES FOR '{username}' =====")
    print(f"Chunks: {chunks}")
    print(f"Total length: {total_length}")
    print(f"Number of shares: {len(shares)}")
    
    # 4. Validate each share
    for i, share in enumerate(shares):
        print(f"\nShare {i+1}/{len(shares)}:")
        print(f"  Raw data: {share[:50]}..." if len(share) > 50 else share)
        
        try:
            # Try to parse as JSON
            parsed = json.loads(share)
            print(f"  Valid JSON: Yes")
            print(f"  JSON structure: {type(parsed).__name__} with {len(parsed)} items")
            
            # For lists, show more details about each item
            if isinstance(parsed, list):
                for j, item in enumerate(parsed):
                    if j < 3:  # Limit to first 3 items for brevity
                        print(f"    Item {j}: {item}")
                    else:
                        print(f"    ... and {len(parsed) - 3} more items")
                        break
        except json.JSONDecodeError:
            print(f"  Valid JSON: No - Could not parse as JSON")
            print(f"  Length: {len(share)} characters")
    
    # 5. Assertions (optional)
    assert chunks > 0, "Should have at least one chunk"
    assert len(shares) == chunks, "Number of shares should match chunk count"
    
    return shares  # Return the shares for further inspection if needed