# Fixture: managed_prefix_list_true
# Expected network_restricted: see directory name (_true|_false|_absent).
terraform {
  required_providers {
    aws = { source = "hashicorp/aws" }
  }
}
provider "aws" { region = "us-east-1" }

resource "aws_ec2_managed_prefix_list" "private" {
  name           = "private"
  address_family = "IPv4"
  max_entries    = 2
  entry { cidr = "10.0.0.0/8" }
  entry { cidr = "192.168.0.0/16" }
}
resource "aws_security_group" "db" {
  name   = "db"
  vpc_id = "vpc-1"
  ingress {
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    prefix_list_ids = [aws_ec2_managed_prefix_list.private.id]
  }
}
resource "aws_db_instance" "main" {
  identifier = "app"
  engine     = "postgres"
  instance_class = "db.t3.micro"
  vpc_security_group_ids = [aws_security_group.db.id]
}

