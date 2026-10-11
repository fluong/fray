# Fixture: unknown_port_protocol_all_false
# Expected network_restricted: see directory name (_true|_false|_absent).
terraform {
  required_providers {
    aws = { source = "hashicorp/aws" }
  }
}
provider "aws" { region = "us-east-1" }

resource "aws_security_group" "db" {
  name   = "db"
  vpc_id = "vpc-1"
  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
resource "aws_db_instance" "main" {
  identifier     = "app"
  engine         = "custom-engine"
  instance_class = "db.t3.micro"
  vpc_security_group_ids = [aws_security_group.db.id]
}

