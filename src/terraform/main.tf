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
  instance_type          = "m5a.xlarge"
  subnet_id              = aws_subnet.demo_subnet.id
  vpc_security_group_ids = [aws_security_group.demo_sg.id]

  # Enable Nitro Enclaves (m5a.large supports enclaves)
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
              yum update -y

              #-----------------------
              # 1) Install Python + FastAPI + Uvicorn
              #-----------------------
              amazon-linux-extras install epel -y
              amazon-linux-extras install python3.8 -y
              yum install -y python3-pip openssl
              pip3 install --upgrade pip
              pip3 install fastapi uvicorn pycryptodome

              #-----------------------
              # 2) Install Docker
              #-----------------------
              amazon-linux-extras install docker -y
              sudo systemctl start docker
              sudo systemctl enable docker

              sudo systemctl status docker

              #-----------------------
              # 3) Install Nitro Enclaves CLI
              #-----------------------
              amazon-linux-extras install aws-nitro-enclaves-cli -y
              yum install -y aws-nitro-enclaves-cli-devel

              # Add ec2-user to 'ne' group so they can run nitro-cli
              usermod -aG ne ec2-user

              #-----------------------
              # 4) Configure Enclave Allocator
              #-----------------------
              sudo cat <<EOT > /etc/nitro_enclaves/allocator.yaml
              version: 1
              memory_mib: 1024
              cpu_count: 2
              EOT

              sudo systemctl enable nitro-enclaves-allocator.service
              sudo systemctl start nitro-enclaves-allocator.service || echo "Allocator service start failed?"

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
                --port 443 \\
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