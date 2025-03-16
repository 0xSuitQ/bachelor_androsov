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

  ingress {
    description   = "HTTPS"
    from_port     = 443
    to_port       = 443
    protocol      = "tcp"
    cidr_blocks   = ["0.0.0.0/0"]
  }

  ingress {
      description   = "HTTPS"
      from_port     = 8443
      to_port       = 8443
      protocol      = "tcp"
      cidr_blocks   = ["0.0.0.0/0"]
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

resource "aws_instance" "demo_ec2" {
  ami                    = data.aws_ami.amazonlinux2.id
  instance_type          = "m5.xlarge"
  subnet_id              = aws_subnet.demo_subnet.id
  vpc_security_group_ids = [aws_security_group.demo_sg.id]

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

              #-----------------------
              # 0) Basic system updates
              #-----------------------
              sudo yum update -y

              #-----------------------
              # 1) Install Python + FastAPI + Uvicorn
              #-----------------------
              sudo amazon-linux-extras install epel -y
              sudo amazon-linux-extras install python3.8 -y
              sudo yum install -y python3-pip openssl
              sudo pip3 install --upgrade pip
              sudo pip3 install fastapi uvicorn pycryptodome

              #-----------------------
              # 2) Install Docker
              #-----------------------
              sudo amazon-linux-extras install docker -y
              sudo systemctl start docker
              sudo systemctl enable docker

              sudo systemctl status docker

              #-----------------------
              # 3) Install Nitro Enclaves CLI
              #-----------------------
              sudo amazon-linux-extras install aws-nitro-enclaves-cli -y
              sudo yum install -y aws-nitro-enclaves-cli-devel

              # Add ec2-user to 'ne' group so they can run nitro-cli
              sudo usermod -aG ne ec2-user

              # 4) Configure Enclave Allocator
              #-----------------------
              # First load the kernel module
              echo "nitro_enclaves" | sudo tee /etc/modules-load.d/nitro_enclaves.conf
              sudo modprobe nitro_enclaves

              # Wait a moment for the module to initialize
              sleep 2

              # Make sure the CLI is properly installed
              sudo yum install -y aws-nitro-enclaves-cli
              sudo yum install -y aws-nitro-enclaves-cli-devel

              # Then configure the allocator
              sudo mkdir -p /etc/nitro_enclaves/
              sudo tee /etc/nitro_enclaves/allocator.yaml > /dev/null << 'EOT'
              ---
              # Enclave configuration file.
              #
              # How much memory to allocate for enclaves (in MiB).
              memory_mib: 1200
              #
              # How many CPUs to reserve for enclaves.
              cpu_count: 2
              #
              # Alternatively, the exact CPUs to be reserved for the enclave can be explicitly
              # configured by using `cpu_pool` (like below), instead of `cpu_count`.
              # Note: cpu_count and cpu_pool conflict with each other. Only use exactly one of them.
              # Example of reserving CPUs 2, 3, and 6 through 9:
              # cpu_pool: 2,3,6-9
              EOT

              sudo systemctl daemon-reload
              sudo systemctl start nitro-enclaves-allocator.service

              # Finally enable and start the service
              sudo systemctl daemon-reload
              sudo systemctl enable nitro-enclaves-allocator.service
              sudo systemctl start nitro-enclaves-allocator.service

              # Check if the device exists
              ls -la /dev/nitro_enclaves || echo "Device file still not created"


              #-----------------------
              # 5) Generate a self-signed SSL certificate
              #-----------------------
              mkdir -p /home/ec2-user/certs
              openssl req -x509 -nodes -days 365 \
                -subj "/CN=localhost" \
                -newkey rsa:2048 \
                -keyout /home/ec2-user/certs/server.key \
                -out /home/ec2-user/certs/server.crt
              chown -R ec2-user:ec2-user /home/ec2-user/certs

              #-----------------------
              # 6) Simple FastAPI app
              #-----------------------
              mkdir -p /home/ec2-user/app
              cat <<APP > /home/ec2-user/app/main.py
              from fastapi import FastAPI

              app = FastAPI()

              @app.get("/")
              def read_root():
                  return {"Hello": "World from HTTPS FastAPI on port 443!"}
              APP

              chown -R ec2-user:ec2-user /home/ec2-user/app

              #-----------------------
              # 7) Systemd service for FastAPI on HTTPS (port 443)
              #-----------------------
              cat <<SERVICE > /etc/systemd/system/fastapi.service
              [Unit]
              Description=FastAPI over HTTPS
              After=network.target

              [Service]
              Type=simple
              User=ec2-user
              WorkingDirectory=/home/ec2-user/app
              ExecStart=/usr/local/bin/uvicorn main:app \\
                --host 0.0.0.0 \\
                --port 8443 \\
                --ssl-certfile /home/ec2-user/certs/server.crt \\
                --ssl-keyfile /home/ec2-user/certs/server.key
              Restart=always

              [Install]
              WantedBy=multi-user.target
              SERVICE

              systemctl daemon-reload
              systemctl enable fastapi.service
              systemctl start fastapi.service

              #-----------------------
              # 8) Quick test for Nitro Enclaves
              #-----------------------
              echo "Testing Nitro CLI..."
              nitro-cli describe-enclaves || echo "No enclaves running or device missing"

              sudo systemctl start docker
              sudo systemctl enable docker

              #-----------------------
              # 9) Setup VSOCK Demo
              #-----------------------
              mkdir -p /home/ec2-user/vsock-demo
              cat <<DOCKERFILE > /home/ec2-user/vsock-demo/Dockerfile.enclave
              FROM public.ecr.aws/amazonlinux/amazonlinux:2

              # Install Python for vsock support
              RUN yum update -y && \\
                  yum install -y python3 procps && \\
                  yum clean all

              # Create directory for our application
              WORKDIR /app

              # Create the Python vsock server script
              RUN echo '#!/usr/bin/env python3' > /app/server.py && \\
                  echo 'import socket' >> /app/server.py && \\
                  echo 'import sys' >> /app/server.py && \\
                  echo '' >> /app/server.py && \\
                  echo 'def main():' >> /app/server.py && \\
                  echo '    # Create vsock socket' >> /app/server.py && \\
                  echo '    s = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)' >> /app/server.py && \\
                  echo '    ' >> /app/server.py && \\
                  echo '    # Bind to port 5005' >> /app/server.py && \\
                  echo '    s.bind((socket.VMADDR_CID_ANY, 5005))' >> /app/server.py && \\
                  echo '    s.listen(5)' >> /app/server.py && \\
                  echo '    ' >> /app/server.py && \\
                  echo '    print("VSOCK server running on port 5005")' >> /app/server.py && \\
                  echo '    ' >> /app/server.py && \\
                  echo '    while True:' >> /app/server.py && \\
                  echo '        conn, addr = s.accept()' >> /app/server.py && \\
                  echo '        print(f"Connection from CID {addr[0]}")' >> /app/server.py && \\
                  echo '        ' >> /app/server.py && \\
                  echo '        data = conn.recv(1024)' >> /app/server.py && \\
                  echo '        if data:' >> /app/server.py && \\
                  echo '            print(f"Received: {data.decode()}")' >> /app/server.py && \\
                  echo '            response = f"Hello from Enclave! Got: {data.decode()}"' >> /app/server.py && \\
                  echo '            conn.send(response.encode())' >> /app/server.py && \\
                  echo '        conn.close()' >> /app/server.py && \\
                  echo '' >> /app/server.py && \\
                  echo 'if __name__ == "__main__":' >> /app/server.py && \\
                  echo '    print("Starting vsock server...")' >> /app/server.py && \\
                  echo '    main()' >> /app/server.py

              # Make it executable
              RUN chmod +x /app/server.py

              # Set the entrypoint
              ENTRYPOINT ["python3", "/app/server.py"]
              DOCKERFILE

              # Create the vsock client script
              cat <<CLIENTPY > /home/ec2-user/vsock-demo/vsock_client.py
              #!/usr/bin/env python3
              import socket
              import sys

              # Check arguments
              if len(sys.argv) != 3:
                  print(f"Usage: {sys.argv[0]} <CID> <message>")
                  sys.exit(1)

              cid = int(sys.argv[1])
              message = sys.argv[2]

              # Create socket
              s = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)

              # Connect to the enclave
              s.connect((cid, 5005))

              # Send message
              print(f"Sending: {message}")
              s.send(message.encode())

              # Receive response
              response = s.recv(1024)
              print(f"Received: {response.decode()}")

              s.close()
              CLIENTPY

              # Make client script executable
              chmod +x /home/ec2-user/vsock-demo/vsock_client.py

              # Set proper ownership
              chown -R ec2-user:ec2-user /home/ec2-user/vsock-demo

              # Build Docker image and EIF file
              cd /home/ec2-user/vsock-demo
              sudo docker build -t nitro-vsock-server:latest -f Dockerfile.enclave .
              nitro-cli build-enclave --docker-uri nitro-vsock-server:latest --output-file vsock-server.eif

              # Create a README with instructions
              cat <<README > /home/ec2-user/vsock-demo/README.txt
              VSOCK Demo for Nitro Enclaves
              -----------------------------

              1. To run the enclave:
                sudo nitro-cli run-enclave --cpu-count 2 --memory 1200 --eif-path vsock-server.eif --debug-mode

              2. Note the CID from the output (e.g. 17)

              3. To test communication:
                ./vsock_client.py <CID> 'Hello from host'

              4. To view enclave console output:
                sudo nitro-cli console --enclave-id <enclave-id>
              README

              echo "VSOCK demo setup complete in /home/ec2-user/vsock-demo"

              EOF

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