# Client-side code
import requests
import os
import base64
from srp import User, create_salted_verification_key

class AuthClient:
    def __init__(self, server_url):
        self.server_url = server_url
        self.user = None
    
    def register(self, username, password):
        try:
            # Create verifier and salt using the password
            salt, verifier = create_salted_verification_key(username, password)
                
            # Convert to hex strings to match server expectations
            salt_hex = salt.hex()
            verifier_hex = verifier.hex()
            
            # Add timeout to prevent hanging
            response = requests.post(
                f"{self.server_url}/register",
                json={'username': username, 'salt': salt_hex, 'verifier': verifier_hex},
                timeout=10
            )
            return response.json()
        except requests.exceptions.Timeout:
            return {"status": "error", "message": "Connection timed out"}
        except requests.exceptions.ConnectionError:
            return {"status": "error", "message": "Could not connect to server"}
        except Exception as e:
            return {"status": "error", "message": f"Error: {str(e)}"}
    
    def login(self, username, password):
        try:
            # Create SRP user 
            self.user = User(username, password)
            
            # Start authentication (generates A)
            self.user.start_authentication()
            
            # Get the public key (A) that needs to be sent to server
            A = self.user.get_ephemeral_secret()
            
            # Convert bytes to hex for JSON transport
            A_hex = A.hex() if isinstance(A, bytes) else A
            
            # Initialize authentication - SEND A TO SERVER
            init_response = requests.post(
                f"{self.server_url}/auth_init",
                json={'username': username, 'A': A_hex},  # Include A here
                timeout=10
            )
            
            # Check response status before parsing JSON
            if init_response.status_code != 200:
                return {
                    "status": "error", 
                    "message": f"Server error: {init_response.status_code} - {init_response.text}"
                }
                
            try:
                init_data = init_response.json()
            except ValueError:
                return {
                    "status": "error", 
                    "message": f"Invalid JSON response: {init_response.text}"
                }
            
            if init_data.get('status') != 'success':
                return init_data

            session_id = init_data.get('session_id')
            salt_hex = init_data.get('salt')
            B_hex = init_data.get('B')
            
            if not all([session_id, salt_hex, B_hex]):
                return {
                    "status": "error", 
                    "message": "Missing required authentication parameters from server"
                }
            
            # Convert hex strings to bytes for the SRP calculation
            salt_bytes = bytes.fromhex(salt_hex)
            B_bytes = bytes.fromhex(B_hex)
            
            # Process challenge returns M1 (client proof)
            M1 = self.user.process_challenge(salt_bytes, B_bytes)
            
            # Convert bytes to hex for JSON transport if needed
            M1_hex = M1.hex() if isinstance(M1, bytes) else M1
            
            # Send proof to server and verify server's response
            verify_response = requests.post(
                f"{self.server_url}/auth_verify",
                json={'client_proof': M1_hex, 'session_id': session_id},
                timeout=10
            )
        
            # Check response status before parsing JSON
            if verify_response.status_code != 200:
                return {
                    "status": "error", 
                    "message": f"Server error during verification: {verify_response.status_code} - {verify_response.text}"
                }
                
            try:
                verify_data = verify_response.json()
            except ValueError:
                return {
                    "status": "error", 
                    "message": f"Invalid JSON response during verification: {verify_response.text}"
                }
            
            return verify_data
        except requests.exceptions.Timeout:
            return {"status": "error", "message": "Connection timed out"}
        except requests.exceptions.ConnectionError:
            return {"status": "error", "message": "Could not connect to server"}
        except Exception as e:
            return {"status": "error", "message": f"Login error: {str(e)}"}


import sys
import os
import argparse
import time
from auth_client import AuthClient

# Colors for terminal output
class Colors:
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    RESET = '\033[0m'

def print_success(message):
    print(f"{Colors.GREEN}✓ {message}{Colors.RESET}")

def print_warning(message):
    print(f"{Colors.YELLOW}⚠ {message}{Colors.RESET}")

def print_error(message):
    print(f"{Colors.RED}✗ {message}{Colors.RESET}")

def test_auth_flow(server_url):
    """Test the complete authentication flow"""
    print(f"Testing ZKP authentication against: {server_url}")
    print("-" * 60)
    
    # Initialize the auth client
    auth_client = AuthClient(server_url)
    
    # Generate unique test credentials
    timestamp = int(time.time())
    username = f"testuser_{timestamp}"
    password = f"testpass_{timestamp}"
    
    # Step 1: Registration
    print(f"Step 1: Registering user '{username}'...")
    try:
        register_result = auth_client.register(username, password)
        
        if register_result.get("status") == "success":
            print_success(f"Registration successful: {register_result.get('message')}")
        else:
            print_error(f"Registration failed: {register_result}")
            return False
    except Exception as e:
        print_error(f"Registration error: {str(e)}")
        return False
    
    # Step 2: Login with correct credentials
    print(f"\nStep 2: Logging in with correct credentials...")
    try:
        login_result = auth_client.login(username, password)
        
        if login_result.get("status") == "success":
            print_success(f"Login successful: {login_result.get('message')}")
        else:
            print_error(f"Login failed: {login_result}")
            return False
    except Exception as e:
        print_error(f"Login error: {str(e)}")
        return False
    
    # Step 3: Login with incorrect credentials (should fail)
    print(f"\nStep 3: Testing with incorrect password (should fail)...")
    try:
        wrong_login_result = auth_client.login(username, password + "_wrong")
        
        if wrong_login_result.get("status") != "success":
            print_success("Login correctly rejected with wrong password")
        else:
            print_error("Security issue: Login succeeded with wrong password!")
            return False
    except Exception as e:
        print_warning(f"Login with wrong password exception: {str(e)}")
    
    print("\n" + "=" * 60)
    print_success("All tests passed! Zero Knowledge Authentication is working.")
    return True

def interactive_test(server_url):
    """Run interactive tests"""
    print("Interactive ZKP Authentication Test")
    print("==================================")
    
    auth_client = AuthClient(server_url)
    
    while True:
        print("\nChoose an option:")
        print("1. Register a new user")
        print("2. Login with existing user")
        print("3. Run automated test")
        print("4. Exit")
        
        choice = input("> ")
        
        if choice == "1":
            username = input("Username: ")
            password = input("Password: ")
            
            try:
                result = auth_client.register(username, password)
                if result.get("status") == "success":
                    print_success(f"Registration successful: {result.get('message')}")
                else:
                    print_error(f"Registration failed: {result}")
            except Exception as e:
                print_error(f"Error: {str(e)}")
                
        elif choice == "2":
            username = input("Username: ")
            password = input("Password: ")
            
            try:
                result = auth_client.login(username, password)
                if result.get("status") == "success":
                    print_success(f"Login successful: {result.get('message')}")
                else:
                    print_error(f"Login failed: {result}")
            except Exception as e:
                print_error(f"Error: {str(e)}")
                
        elif choice == "3":
            test_auth_flow(server_url)
            
        elif choice == "4":
            print("Exiting...")
            break
            
        else:
            print_warning("Invalid option")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Test Zero Knowledge Authentication")
    parser.add_argument("--server", default="http://44.205.14.101:8080", 
                        help="Authentication server URL")
    parser.add_argument("--interactive", action="store_true", 
                        help="Run in interactive mode")
    
    args = parser.parse_args()
    
    if args.interactive:
        interactive_test(args.server)
    else:
        test_auth_flow(args.server)