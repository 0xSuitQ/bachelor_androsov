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
  vpc_id = aws_vpc.demo_vpc.id
  tags = {
    Name = "DemoSG"
  }

  ingress {
    description      = "SSH"
    from_port        = 22
    to_port          = 22
    protocol         = "tcp"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = []
    prefix_list_ids  = []
    security_groups  = []
    self             = false
  }

  ingress {
    description      = "FastAPI Port"
    from_port        = 8000
    to_port          = 8000
    protocol         = "tcp"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = []
    prefix_list_ids  = []
    security_groups  = []
    self             = false
  }

  egress {
    description      = "All traffic"
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = []
    prefix_list_ids  = []
    security_groups  = []
    self             = false
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
  instance_type          = "m5a.large" 
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
              set -e

              ### 1) Basic system updates
              yum update -y

              ### 2) Install Python 3 + pip + FastAPI + Uvicorn
              amazon-linux-extras install epel -y
              amazon-linux-extras install python3.8 -y
              yum install -y python3-pip

              pip3 install --upgrade pip
              pip3 install fastapi uvicorn

              ### 3) Install Nitro Enclaves CLI 
              amazon-linux-extras install aws-nitro-enclaves-cli -y
              yum install -y aws-nitro-enclaves-cli-devel
              nitro-cli --help

              ### 4) Create log directory and set permissions
              mkdir -p /var/log/nitro_enclaves
              touch /var/log/nitro_enclaves/nitro_enclaves.log
              chown root:ne /var/log/nitro_enclaves/nitro_enclaves.log
              chmod 660 /var/log/nitro_enclaves/nitro_enclaves.log

              ### 5) Configure Nitro Enclaves allocation
              # bash -c 'cat <<EOT > /etc/nitro_enclaves/allocator.yaml
              # version: 1
              # memory_mib: 1024
              # cpu_count: 2
              # EOT'

              # systemctl restart nitro-enclaves-allocator.service || echo "Failed to restart nitro-enclaves-allocator.service"

              ### 6) Add current user (ec2-user) to ne group so they can use nitro-cli
              usermod -aG ne ec2-user

              ### 7) Create FastAPI application directory and main.py file
              mkdir -p /home/ec2-user/app
              bash -c 'cat <<EOT > /home/ec2-user/app/main.py
              from fastapi import FastAPI

              app = FastAPI()

              @app.get("/")
              def read_root():
                  return {"Hello": "World"}

              @app.get("/items/{item_id}")
              def read_item(item_id: int, q: str = None):
                  return {"item_id": item_id, "q": q}
              EOT'

              ### 8) Create systemd service file for FastAPI application
              bash -c 'cat <<EOT > /etc/systemd/system/fastapi.service
              [Unit]
              Description=FastAPI application

              [Service]
              ExecStart=/usr/local/bin/uvicorn main:app --host 0.0.0.0 --port 8000
              WorkingDirectory=/home/ec2-user/app
              Restart=always
              User=ec2-user

              [Install]
              WantedBy=multi-user.target
              EOT'

              ### 9) Start and enable FastAPI service
              systemctl daemon-reload
              systemctl start fastapi.service
              systemctl enable fastapi.service

              ### 10) Simple Test: Check if we can run 'nitro-cli describe-enclaves'
              echo "Testing Nitro Enclaves..."
              nitro-cli describe-enclaves || echo "Check if enclaves are supported."

              ### Debugging: Verify creation
              ls -la /home/ec2-user/app
              EOF

  tags = {
    Name = "DemoEC2withNitro"
  }
}

output "ec2_public_ip" {
  value       = aws_instance.demo_ec2.public_ip
  description = "Public IP of the new instance"
}

output "ec2_public_dns" {
  value       = aws_instance.demo_ec2.public_dns
  description = "Public DNS of the new instance"
}
