#!/bin/bash
set -e  # Exit on any error

echo "Starting Secure Key Management Enclave Setup..."

mkdir -p /home/ec2-user/secure-enclave

cat <<DOCKERFILE > /home/ec2-user/secure-enclave/Dockerfile.enclave
FROM public.ecr.aws/amazonlinux/amazonlinux:2

RUN yum update -y && \\
	yum install -y python3 python3-pip procps && \\
	pip3 install pycryptodome && \\
	yum clean all

WORKDIR /app

COPY key_server.py /app/
RUN chmod +x /app/key_server.py

ENTRYPOINT ["python3", "-u", "/app/key_server.py"]
DOCKERFILE

sudo cat <<PYSERVER > /home/ec2-user/secure-enclave/key_server.py
#!/usr/bin/env python3
import socket
import json
import os
import base64
import sys
import time
import traceback
import random
from Crypto.Cipher import AES

PRIME = 2**256 - 2**224 + 2**192 + 2**96 - 1
MASTER_KEY = None

def mod_inverse(k, prime):
	"""Calculate the modular multiplicative inverse of k modulo prime"""
	s, old_s = 0, 1
	t, old_t = 1, 0
	r, old_r = prime, k
	
	while r != 0:
		quotient = old_r // r
		old_r, r = r, old_r - quotient * r
		old_s, s = s, old_s - quotient * s
		old_t, t = t, old_t - quotient * t
	
	return old_s % prime

def evaluate_polynomial(coefficients, x, prime):
	result = 0
	for coef in reversed(coefficients):
		result = (result * x + coef) % prime
	return result

def split_secret(secret, threshold, total_shares, prime=PRIME):
	if secret >= prime:
		raise ValueError("Secret must be smaller than the prime")
	
	coefficients = [secret]
	for _ in range(threshold - 1):
		coefficients.append(random.randint(1, prime - 1))
	
	shares = []
	for x in range(1, total_shares + 1):
		y = evaluate_polynomial(coefficients, x, prime)
		shares.append((x, y))
	
	return shares

def reconstruct_secret(shares, prime=PRIME):
	"""Reconstruct the secret from shares using Lagrange interpolation"""
	if len(shares) == 0:
		raise ValueError("Need at least one share")
	
	secret = 0
	x_coords = [x for x, _ in shares]
	
	for i, (x_i, y_i) in enumerate(shares):
		numerator = 1
		denominator = 1
		
		for j, x_j in enumerate(x_coords):
			if i != j:
				numerator = (numerator * (0 - x_j)) % prime
				denominator = (denominator * (x_i - x_j)) % prime
		
		lagrange_term = (y_i * numerator * mod_inverse(denominator, prime)) % prime
		secret = (secret + lagrange_term) % prime
	
	return secret

def bytes_to_int(data):
	"""Convert bytes to integer for Shamir's Secret Sharing"""
	return int.from_bytes(data, byteorder='big')

def int_to_bytes(number, length):
	"""Convert integer back to bytes with given length"""
	return number.to_bytes(length, byteorder='big')


def generate_master_key():
	"""Generate a master key for the enclave"""
	global MASTER_KEY
	if MASTER_KEY is None:
		MASTER_KEY = os.urandom(32)  # 256-bit key
		print(f"Master key generated: {base64.b64encode(MASTER_KEY[:4]).decode()}... (first 4 bytes)")
	return MASTER_KEY

def generate_user_key():
	"""Generate a new key for a user"""
	return os.urandom(32)

def split_encrypted_key(encrypted_data, total_shares=5, threshold=3):
	"""Split encrypted key data into shares using SSSS"""
	chunk_size = 30
	chunks = [encrypted_data[i:i+chunk_size] for i in range(0, len(encrypted_data), chunk_size)]
	print(f"Split encrypted data into {len(chunks)} chunks")
	
	all_shares = []
	for i, chunk in enumerate(chunks):
		chunk_int = bytes_to_int(chunk)
		
		chunk_shares = split_secret(chunk_int, threshold, total_shares)
		
		formatted_shares = []
		for x, y in chunk_shares:
			formatted_shares.append((str(x), str(y), str(i), str(len(chunk))))
		
		all_shares.append(formatted_shares)
	
	return {
		"chunks": len(chunks),
		"shares": all_shares,
		"total_length": len(encrypted_data)
	}

def combine_key_shares(share_data):
	"""Combine key shares into the original encrypted key. Receives JSON"""
	chunks_count = share_data["chunks"]
	all_shares_raw = share_data["shares"]
	total_length = share_data["total_length"]

	all_shares = []
	for share_str in all_shares_raw:
		if isinstance(share_str, str):
			try:
				parsed_share = json.loads(share_str)
				all_shares.append(parsed_share)
			except json.JSONDecodeError as e:
				print(f"JSON decode error: {e} on string: {share_str[:50]}...")
				raise ValueError(f"Invalid share format")
		else:
			all_shares.append(share_str)
	
	print(f"Parsed {len(all_shares)} shares for {chunks_count} chunks")
	
	# Reconstruct each chunk
	reconstructed_chunks = []
	
	for chunk_shares in all_shares:
		chunk_index = int(chunk_shares[0][2])
		chunk_length = int(chunk_shares[0][3])
		
		numeric_shares = [(int(x), int(y)) for x, y, _, _ in chunk_shares]
		
		chunk_int = reconstruct_secret(numeric_shares)
		
		chunk_bytes = int_to_bytes(chunk_int, chunk_length)
		reconstructed_chunks.append((chunk_index, chunk_bytes))
	
	reconstructed_chunks.sort(key=lambda x: x[0])
	reconstructed_data = b''.join([chunk for _, chunk in reconstructed_chunks])
	
	return reconstructed_data

def encrypt_with_master_key(data):
	"""Encrypt data with the master key using AES-GCM"""
	nonce = os.urandom(12)

	cipher = AES.new(MASTER_KEY, AES.MODE_GCM, nonce=nonce)
	ciphertext, tag = cipher.encrypt_and_digest(data)
	return nonce + tag + ciphertext

def decrypt_with_master_key(encrypted_data):
	"""Decrypt data with the master key using AES-GCM"""
	nonce = encrypted_data[:12]
	tag = encrypted_data[12:28]  # 16-byte authentication tag
	ciphertext = encrypted_data[28:]
	
	cipher = AES.new(MASTER_KEY, AES.MODE_GCM, nonce=nonce)
	
	try:
		plaintext = cipher.decrypt_and_verify(ciphertext, tag)
		return plaintext
	except ValueError:
		raise SecurityError("Decryption failed: authentication tag verification failed")

def handle_request(request):
	"""Handle client requests"""
	try:
		action = request.get("action", "")
		print(f"Processing action: {action}")
		
		if action == "ping":
			return {
				"status": "success",
				"message": "Enclave running",
				"echo": request
			}
			
		elif action == "register":
			username = request.get("username")
			if not username:
				return {"status": "error", "message": "Username required"}
			
			generate_master_key()
			
			user_key = generate_user_key()
			
			encrypted_key = encrypt_with_master_key(user_key)

			total_shares = 5
			threshold = 3
			key_shares = split_encrypted_key(encrypted_key, total_shares, threshold)
			
			return {
				"status": "success",
				"result": {
					"key_shares": key_shares,
					"decrypted_key": base64.b64encode(user_key).decode()
				}
			}
			
		elif action == "auth_verify": 
			key_shares = request.get("key_shares")
			if not key_shares:
				return {"status": "error", "message": "Key shares required"}
			
			generate_master_key()

			try:
				encrypted_key = combine_key_shares(key_shares)
				decrypted_key = decrypt_with_master_key(encrypted_key)                

				return {
					"status": "success",
					"result": {
						"decrypted_key": base64.b64encode(decrypted_key).decode()
					}
				}
			except Exception as e:
				print(f"Decryption error: {e}")
				return {"status": "error", "message": f"Key decryption failed: {str(e)}"}
				
		else:
			return {"status": "error", "message": f"Unknown action: {action}"}
			
	except Exception as e:
		print(f"Error handling request: {e}")
		traceback.print_exc()
		return {"status": "error", "message": f"Internal error: {str(e)}"}

def main():
	print("=== Starting Key Management VSOCK Server in Nitro Enclave ===")
	
	generate_master_key()
	
	s = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
	s.bind((socket.VMADDR_CID_ANY, 5005))
	s.listen(5)
	print("VSOCK server running on port 5005")

	while True:
		print("Waiting for connections...")
		conn, addr = s.accept()
		print(f"Connection from CID {addr[0]}")
		
		try:
			data = conn.recv(4096)
			if data:
				print(f"Received data: {data[:100]}...")
				
				request = json.loads(data.decode())
				
				response = handle_request(request)
				
				conn.send(json.dumps(response).encode())
				print("Response sent")
		except Exception as e:
			print(f"Error processing request: {e}")
			traceback.print_exc()
			error_response = {"status": "error", "message": f"Request processing error: {str(e)}"}
			conn.send(json.dumps(error_response).encode())
		finally:
			conn.close()

if __name__ == "__main__":
	while True:
		try:
			main()
		except Exception as e:
			print(f"Server error: {e}")
			traceback.print_exc()
			time.sleep(5)  # Wait before retrying
PYSERVER

chmod +x /home/ec2-user/secure-enclave/key_server.py
chown -R ec2-user:ec2-user /home/ec2-user/secure-enclave

cd /home/ec2-user/secure-enclave/
echo "Building Docker image..."
sudo docker build -t keymanager:latest -f Dockerfile.enclave .

echo "Building enclave image file..."
sudo nitro-cli build-enclave --docker-uri keymanager:latest --output-file keymanager.eif

cat <<RUNSCRIPT > /home/ec2-user/secure-enclave/run_enclave.sh
#!/bin/bash
echo "Starting Nitro Enclave manually..."
sudo nitro-cli run-enclave --cpu-count 2 --memory 1200 --eif-path /home/ec2-user/secure-enclave/keymanager.eif --enclave-name keymanager --debug-mode
RUNSCRIPT

chmod +x /home/ec2-user/secure-enclave/run_enclave.sh
chown ec2-user:ec2-user /home/ec2-user/secure-enclave/run_enclave.sh

echo "Starting Nitro Enclave..."
RUNNING_ENCLAVE=$(sudo nitro-cli describe-enclaves)
if [ "$RUNNING_ENCLAVE" == "[]" ]; then
	cd /home/ec2-user/secure-enclave/
	sudo nitro-cli run-enclave --cpu-count 2 --memory 1200 --eif-path keymanager.eif --enclave-name keymanager --debug-mode &
	echo "Enclave startup initiated"
	sleep 5
	sudo nitro-cli describe-enclaves
else
	echo "Enclave already running"
fi