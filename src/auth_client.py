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
            self.user = User(username, password)
            
            self.user.start_authentication()
            
            A = self.user.get_ephemeral_secret()
            
            # Convert bytes to hex for JSON transport
            A_hex = A.hex() if isinstance(A, bytes) else A
            
            init_response = requests.post(
                f"{self.server_url}/auth_init",
                json={'username': username, 'A': A_hex}, 
                timeout=10
            )
            
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
            
            salt_bytes = bytes.fromhex(salt_hex)
            B_bytes = bytes.fromhex(B_hex)
            
            M1 = self.user.process_challenge(salt_bytes, B_bytes)
            
            M1_hex = M1.hex() if isinstance(M1, bytes) else M1
            
            verify_response = requests.post(
                f"{self.server_url}/auth_verify",
                json={'client_proof': M1_hex, 'session_id': session_id},
                timeout=10
            )
        
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
