############################
# Terraform Configuration
############################
terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 4.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.0"
    }
    # Add this line:
    local = {
      source  = "hashicorp/local"
      version = "~> 2.1.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

############################
# Networking Setup
############################
resource "aws_vpc" "demo_vpc" {
  cidr_block = "10.0.0.0/16"
  tags = {
    Name = "DemoVPC"
  }
}

resource "aws_internet_gateway" "demo_igw" {
  vpc_id = aws_vpc.demo_vpc.id
  tags = {
    Name = "DemoIGW"
  }
}

resource "aws_subnet" "demo_subnet" {
  vpc_id                  = aws_vpc.demo_vpc.id
  cidr_block             = "10.0.1.0/24"
  availability_zone       = "us-east-1a"
  map_public_ip_on_launch = true
  tags = {
    Name = "DemoSubnet"
  }
}

resource "aws_route_table" "demo_routetable" {
  vpc_id = aws_vpc.demo_vpc.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.demo_igw.id
  }
  tags = {
    Name = "DemoRouteTable"
  }
}

resource "aws_route_table_association" "demo_rta" {
  route_table_id = aws_route_table.demo_routetable.id
  subnet_id      = aws_subnet.demo_subnet.id
}

############################
# Security Group
############################
resource "aws_security_group" "demo_sg" {
  name        = "DemoSG-HTTPS"
  description = "Allow inbound HTTPS + SSH"
  vpc_id      = aws_vpc.demo_vpc.id

  # Inbound
  ingress {
    description   = "SSH (Not recommended open to all in production!)"
    from_port     = 22
    to_port       = 22
    protocol      = "tcp"
    cidr_blocks   = ["0.0.0.0/0"]
  }

  # ingress {
  #   description   = "HTTPS"
  #   from_port     = 443
  #   to_port       = 443
  #   protocol      = "tcp"
  #   cidr_blocks   = ["0.0.0.0/0"]
  # }

  # ingress {
  #     description   = "HTTPS"
  #     from_port     = 8443
  #     to_port       = 8443
  #     protocol      = "tcp"
  #     cidr_blocks   = ["0.0.0.0/0"]
  #   }

    ingress {
      description = "HTTP for FastAPI"
      from_port   = 8080
      to_port     = 8080
      protocol    = "tcp"
      cidr_blocks = ["0.0.0.0/0"]
    }

  # Outbound
  egress {
    description   = "All traffic"
    from_port     = 0
    to_port       = 0
    protocol      = "-1"
    cidr_blocks   = ["0.0.0.0/0"]
  }

  tags = {
    Name = "DemoSG-HTTPS"
  }
}

############################
# S3 Bucket for Scripts
############################
resource "aws_s3_bucket" "scripts_bucket" {
  bucket = "nitro-enclave-scripts-${random_id.bucket_suffix.hex}"
  
  tags = {
    Name = "NitroEnclaveScriptsBucket"
  }
}

resource "aws_s3_object" "enclave_setup_script" {
  bucket = aws_s3_bucket.scripts_bucket.id
  key    = "enclave_setup.sh"
  source = "${path.module}/enclave_setup.sh"
  etag   = filemd5("${path.module}/enclave_setup.sh")
}

# Generate a random suffix for the bucket name to ensure uniqueness
resource "random_id" "bucket_suffix" {
  byte_length = 4
}

# First set ownership controls to enable ACLs
resource "aws_s3_bucket_ownership_controls" "scripts_bucket_ownership" {
  bucket = aws_s3_bucket.scripts_bucket.id

  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

# Then set the ACL (with dependency)
resource "aws_s3_bucket_acl" "scripts_bucket_acl" {
  depends_on = [aws_s3_bucket_ownership_controls.scripts_bucket_ownership]
  bucket     = aws_s3_bucket.scripts_bucket.id
  acl        = "private"
}

############################
# EC2 Instance
############################
data "aws_ami" "amazonlinux2" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["amzn2-ami-kernel-*-hvm-2.0*"]
  }
}

resource "aws_iam_role" "ec2_s3_access" {
  name = "ec2_s3_access"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy" "s3_access_policy" {
  name = "s3_access_policy"
  role = aws_iam_role.ec2_s3_access.id
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "s3:GetObject"
        ]
        Effect = "Allow"
        Resource = "${aws_s3_bucket.scripts_bucket.arn}/*"
      }
    ]
  })
}

resource "aws_iam_instance_profile" "ec2_profile" {
  name = "ec2_s3_access_profile"
  role = aws_iam_role.ec2_s3_access.name
}

resource "aws_instance" "demo_ec2" {
  ami                    = data.aws_ami.amazonlinux2.id
  instance_type          = "m5.xlarge"
  subnet_id              = aws_subnet.demo_subnet.id
  vpc_security_group_ids = [aws_security_group.demo_sg.id]
  iam_instance_profile   = aws_iam_instance_profile.ec2_profile.name

  # Enable Nitro Enclaves (m5a.large supports enclaves)
  enclave_options {
    enabled = true
  }

  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "optional"
  }

  # Cloud-Init / User Data to install dependencies
  user_data = <<-EOF
              #!/bin/bash
              sudo yum update -y
              # 1) Install Python + FastAPI + Uvicorn
              sudo amazon-linux-extras install epel -y
              sudo amazon-linux-extras install python3.8 -y
              sudo yum install -y python3-pip openssl
              sudo pip3 install --upgrade pip
              sudo pip3 install "urllib3<2.0" requests
              sudo pip3 install fastapi uvicorn pycryptodome srp web3 python-dotenv

              # 2) Install Docker
              sudo amazon-linux-extras install docker -y
              sudo systemctl start docker
              sudo systemctl enable docker
              sudo systemctl status docker

              # 3) Install Nitro Enclaves CLI
              sudo amazon-linux-extras install aws-nitro-enclaves-cli -y
              sudo yum install -y aws-nitro-enclaves-cli-devel
              sudo usermod -aG ne ec2-user

              # 4) Configure Enclave Allocator
              # First load the kernel module
              echo "nitro_enclaves" | sudo tee /etc/modules-load.d/nitro_enclaves.conf
              sudo modprobe nitro_enclaves
              sleep 2
              sudo yum install -y aws-nitro-enclaves-cli
              sudo yum install -y aws-nitro-enclaves-cli-devel
              sudo mkdir -p /etc/nitro_enclaves/
              sudo tee /etc/nitro_enclaves/allocator.yaml > /dev/null << 'EOT'
              ---
              memory_mib: 1200
              cpu_count: 2
              EOT

              sudo systemctl daemon-reload
              sudo systemctl start nitro-enclaves-allocator.service
              sudo systemctl daemon-reload
              sudo systemctl enable nitro-enclaves-allocator.service
              sudo systemctl start nitro-enclaves-allocator.service

              # Check if the device exists
              ls -la /dev/nitro_enclaves || echo "Device file still not created"

              # 5) Generate a self-signed SSL certificate              
              IP=$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4)
              mkdir -p /home/ec2-user/certs
              # build a minimal req.conf with SAN
              cat > /home/ec2-user/certs/req.cnf <<-SANCFG
                [req]
                distinguished_name = req_distinguished_name
                req_extensions     = v3_req
                prompt             = no

                [req_distinguished_name]
                CN = $${IP}

                [v3_req]
                subjectAltName = @alt_names

                [alt_names]
                IP.1 = $${IP}
              SANCFG

              openssl req -x509 -nodes -days 365 \
                -newkey rsa:2048 \
                -keyout /home/ec2-user/certs/server.key \
                -out    /home/ec2-user/certs/server.crt \
                -extensions v3_req \
                -config     /home/ec2-user/certs/req.cnf

              chown -R ec2-user:ec2-user /home/ec2-user/certs

              # 6) Enhanced FastAPI app with Enclave Integration
              mkdir -p /home/ec2-user/app
              curl -s https://raw.githubusercontent.com/0xSuitQ/graduation_abi/main/contract_abi.json > /home/ec2-user/app/contract_abi.json
              chown ec2-user:ec2-user /home/ec2-user/app/contract_abi.json
              cat > /home/ec2-user/app/.env <<ENVFILE
              SERVER_PRIVATE_KEY=${var.server_private_key}
              ENVFILE
              chmod 600 /home/ec2-user/app/.env
              chown ec2-user:ec2-user /home/ec2-user/app/.env

              cat <<APP > /home/ec2-user/app/main.py
              from fastapi import FastAPI, HTTPException
              from pydantic import BaseModel
              from typing import Dict, Any, Optional
              from srp import Verifier
              from web3 import Web3
              from dotenv import load_dotenv
              import uuid
              import socket
              import json
              import os

              app = FastAPI()
              load_dotenv()

              w3 = Web3(Web3.HTTPProvider('https://rpc-amoy.polygon.technology'))
              with open('/home/ec2-user/app/contract_abi.json', 'r') as f:
                  contract_abi = json.load(f)
              contract_address = Web3.to_checksum_address("0x6b017cbf9ffbdd70e2b8a78ef06c163ab722784c")
              contract = w3.eth.contract(address=contract_address, abi=contract_abi)
              server_private_key = os.getenv('SERVER_PRIVATE_KEY')
              server_account = w3.eth.account.from_key(server_private_key)

              users_db = {}
              active_sessions = {}

              ENCLAVE_CID = None

              def execute_contract_tx(func, *args):
                  estimated_gas = func(*args).estimate_gas({'from': server_account.address})
                  gas_limit = int(estimated_gas * 1.1)
                  tx = func(*args).build_transaction({
                      'from': server_account.address,
                      'nonce': w3.eth.get_transaction_count(server_account.address),
                      'gas': gas_limit,
                      'gasPrice': w3.eth.gas_price,
                      'chainId': w3.eth.chain_id
                  })
                  signed_tx = w3.eth.account.sign_transaction(tx, server_private_key)
                  tx_hash = w3.eth.send_raw_transaction(signed_tx.rawTransaction)
                  return w3.eth.wait_for_transaction_receipt(tx_hash)

              def call_contract_view(func, *args):
                  """Call a contract view function that doesn't modify state"""
                  return func(*args).call({'from': server_account.address})

              def store_key_shares(username, shares_data):
                  try:
                      user_exists = call_contract_view(contract.functions.userExists, username)
                      if user_exists:
                          print(f"User {username} already exists in contract")
                          return True
                      
                      chunks = shares_data.get('chunks', 0)
                      total_length = shares_data.get('total_length', 0)
                      shares_raw = shares_data.get('shares', [])
                      serialized_shares = []

                      serialized_shares = [
                          share if isinstance(share, str) else json.dumps(share)
                          for share in shares_raw
                      ]
                      
                      receipt = execute_contract_tx(
                          contract.functions.storeKeyShares,
                          username,
                          chunks,
                          total_length,
                          serialized_shares
                      )
                      success = receipt.status == 1
                      return success
                  except Exception as e:
                      print(f"Error storing key shares: {str(e)}")
                      return False

              def retrieve_key_shares(username):
                  """Retrieve key shares from the blockchain"""
                  try:
                      user_exists = call_contract_view(contract.functions.userExists, username)
                      if not user_exists:
                          print(f"User {username} not found in contract")
                          return None
                
                      chunks, total_length, serialized_shares = call_contract_view(
                          contract.functions.retrieveKeyShares, 
                          username
                      )
                      
                      return {
                          'chunks': chunks,
                          'total_length': total_length,
                          'shares': serialized_shares
                      }
                  except Exception as e:
                      print(f"Error retrieving key shares: {str(e)}")
                      return None

              def get_enclave_cid():
                  import subprocess
                  try:
                      result = subprocess.run(['nitro-cli', 'describe-enclaves'], 
                                            capture_output=True, text=True, check=True)
                      enclaves = json.loads(result.stdout)
                      for enclave in enclaves:
                          if enclave.get('EnclaveName') == 'keymanager':
                              return enclave.get('EnclaveCID')
                      return None
                  except Exception as e:
                      print(f"Error getting enclave CID: {e}")
                      return None

              def send_to_enclave(request):
                  global ENCLAVE_CID
                  
                  if ENCLAVE_CID is None:
                      ENCLAVE_CID = get_enclave_cid()
                      if ENCLAVE_CID is None:
                          raise HTTPException(status_code=500, detail="Enclave not running")
                  
                  s = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
                  try:
                      s.connect((int(ENCLAVE_CID), 5005))
                      s.send(json.dumps(request).encode())
                      response = s.recv(4096).decode()
                      return json.loads(response)
                  except Exception as e:
                      print(f"Error communicating with enclave: {e}")
                      raise HTTPException(status_code=500, detail=f"Enclave communication error: {str(e)}")
                  finally:
                      s.close()

              class RegisterRequest(BaseModel):
                  username: str
                  salt: str
                  verifier: str

              class AuthInitRequest(BaseModel):
                  username: str
                  A: str = None

              class AuthVerifyRequest(BaseModel):
                  client_proof: str
                  session_id: str = None

              @app.get("/")
              def read_root():
                  return {"status": "success", "message": "Authentication Server with Secure Enclave"}

              @app.post("/register")
              def register(request: RegisterRequest):
                  if request.username in users_db:
                      return {"status": "error", "message": "Username already exists"}
                  
                  try:
                      enclave_response = send_to_enclave({
                          'action': 'register',
                          'username': request.username,
                      })
                      
                      if enclave_response.get('status') != 'success':
                          error_message = enclave_response.get('message', 'Failed to generate secure key')
                          print(f"Enclave error during registration: {error_message}")
                          return {"status": "error", "message": f"Enclave error: {error_message}"}
                      
                      key_data = enclave_response.get('result', {})
                      key_shares = key_data.get('key_shares')
                      decrypted_key = key_data.get('decrypted_key')
                      
                      if not key_shares or not decrypted_key:
                          return {"status": "error", "message": "Enclave returned incomplete key data"}
                      
                      blockchain_store_success = store_key_shares(
                          request.username, 
                          {
                              'chunks': key_shares.get('chunks', 0),
                              'total_length': key_shares.get('total_length', 0),
                              'shares': key_shares.get('shares', [])
                          }
                      )
                      
                      if not blockchain_store_success:
                          return {"status": "error", "message": "Failed to store key shares in blockchain"}

                      users_db[request.username] = {
                          "salt": request.salt,
                          "verifier": request.verifier
                      }
                      
                      return {
                          "status": "success", 
                          "message": "User registered successfully",
                          "decrypted_key": decrypted_key
                      }
                      
                  except Exception as e:
                      print(f"Unexpected error during registration: {str(e)}")
                      import traceback
                      traceback.print_exc()
                      return {"status": "error", "message": f"Registration failed: {str(e)}"}

              @app.post("/auth_init")
              def auth_init(request: AuthInitRequest):
                  """Initialize authentication by providing salt and challenge B"""
                  username = request.username
                  A_hex = request.A

                  if A_hex and isinstance(A_hex, str):
                      try:
                          A_bytes = bytes.fromhex(A_hex)
                      except ValueError:
                          return {"status": "error", "message": "Invalid A format"}
                  else:
                      return {"status": "error", "message": "Client public key (A) required"}
                  
                  if username not in users_db:
                      return {"status": "error", "message": "User not found"}
                  
                  try:
                      user_data = users_db[username]
                      salt_hex = user_data["salt"]
                      verifier_hex = user_data["verifier"]
                      
                      if isinstance(salt_hex, str):
                          salt_bytes = bytes.fromhex(salt_hex)
                      else:
                          salt_bytes = salt_hex
                          
                      if isinstance(verifier_hex, str):
                          verifier_bytes = bytes.fromhex(verifier_hex)
                      else:
                          verifier_bytes = verifier_hex
                      
                      verifier = Verifier(username, salt_bytes, verifier_bytes, A_bytes)
                      
                      _, B = verifier.get_challenge()
                      
                      B_hex = B.hex() if isinstance(B, bytes) else B
                      
                      session_id = str(uuid.uuid4())
                      active_sessions[session_id] = {
                          'username': username,
                          'verifier': verifier
                      }
                      
                      return {
                          "status": "success", 
                          "salt": salt_hex,
                          "B": B_hex,
                          "session_id": session_id
                      }
                  except Exception as e:
                      print(f"Error in auth_init: {e}")
                      import traceback
                      traceback.print_exc()
                      return {"status": "error", "message": f"Authentication initialization error: {str(e)}"}

              @app.post("/auth_verify")
              def auth_verify(request: AuthVerifyRequest):
                  """Verify the client's proof and return server proof"""
                  client_proof = request.client_proof
                  session_id = request.session_id
                  
                  if not session_id or session_id not in active_sessions:
                      return {"status": "error", "message": "Invalid or expired session"}
                  
                  session = active_sessions[session_id]
                  verifier = session['verifier']
                  username = session['username']
                  
                  try:
                      if isinstance(client_proof, str):
                          try:
                              client_proof_bytes = bytes.fromhex(client_proof)
                          except ValueError:
                              return {"status": "error", "message": "Invalid client proof format"}
                      else:
                          client_proof_bytes = client_proof
                      
                      # Verify the client's proof
                      server_proof = verifier.verify_session(client_proof_bytes)
                      
                      server_proof_hex = server_proof.hex() if isinstance(server_proof, bytes) else server_proof
                      
                      del active_sessions[session_id]
                      
                      key_shares = retrieve_key_shares(username)
                      
                      if key_shares:
                          # Send the key shares to the enclave for reconstruction
                          enclave_response = send_to_enclave({
                              'action': 'auth_verify',
                              'key_shares': key_shares
                          })
                          
                          # Successfully authenticated - return server proof and decrypted key
                          if enclave_response.get('status') == 'success':
                              decrypted_key = enclave_response.get('result', {}).get('decrypted_key')
                              print("decrypted key:", decrypted_key)
                              
                              return {
                                  "status": "success",
                                  "server_proof": server_proof_hex,
                                  "decrypted_key": decrypted_key
                              }
                      
                      # Successful authentication but key retrieval failed
                      return {
                          "status": "success",
                          "server_proof": server_proof_hex,
                          "message": "Authentication successful but key retrieval failed"
                      }
                  except Exception as e:
                      if session_id in active_sessions:
                          del active_sessions[session_id]
                      print(f"Error in auth_verify: {e}")
                      import traceback
                      traceback.print_exc()
                      return {"status": "error", "message": str(e)}

              @app.on_event("startup")
              async def startup_event():
                  global ENCLAVE_CID
                  ENCLAVE_CID = get_enclave_cid()
              APP

              cat <<HELPER > /home/ec2-user/app/enclave_utils.py
              import socket
              import json
              import subprocess

              def get_enclave_cid():
                  """Get the CID of the running keymanager enclave"""
                  try:
                      result = subprocess.run(['nitro-cli', 'describe-enclaves'], 
                                            capture_output=True, text=True, check=True)
                      enclaves = json.loads(result.stdout)
                      for enclave in enclaves:
                          if enclave.get('EnclaveName') == 'keymanager':
                              return enclave.get('EnclaveCID')
                      return None
                  except Exception as e:
                      print(f"Error getting enclave CID: {e}")
                      return None

              def send_to_enclave(cid, request):
                  """Send a request to the enclave and return the response"""
                  s = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
                  try:
                      s.connect((int(cid), 5005))
                      s.send(json.dumps(request).encode())
                      response = s.recv(4096).decode()
                      return json.loads(response)
                  finally:
                      s.close()

              HELPER

              chown -R ec2-user:ec2-user /home/ec2-user/app

              # 7) Systemd service for FastAPI on HTTPS (port 443)
              cat <<SERVICE > /etc/systemd/system/fastapi.service
              [Unit]
              Description=FastAPI over HTTPS
              After=network.target

              [Service]
              Type=simple
              User=ec2-user
              WorkingDirectory=/home/ec2-user/app
              ExecStart=/usr/local/bin/uvicorn main:app \
                --host 0.0.0.0 \
                --port 8080
              Restart=always

              [Install]
              WantedBy=multi-user.target
              SERVICE

              systemctl daemon-reload
              systemctl enable fastapi.service
              systemctl start fastapi.service

              # 8) Quick test for Nitro Enclaves
              echo "Testing Nitro CLI..."
              nitro-cli describe-enclaves || echo "No enclaves running or device missing"

              sudo systemctl start docker
              sudo systemctl enable docker

              # 9) Download and run the Secure Key Management Enclave setup
              yum install -y aws-cli
              aws s3 cp s3://${aws_s3_bucket.scripts_bucket.id}/enclave_setup.sh /tmp/
              chmod +x /tmp/enclave_setup.sh
              /tmp/enclave_setup.sh
              EOF
  depends_on = [
    aws_s3_object.enclave_setup_script
  ]

  tags = {
    Name = "DemoEC2withNitro-HTTPS"
  }
}

output "ec2_public_ip" {
  value       = aws_instance.demo_ec2.public_ip
  description = "Public IP of the instance"
}

output "ec2_public_dns" {
  value       = aws_instance.demo_ec2.public_dns
  description = "Public DNS of the instance"
}