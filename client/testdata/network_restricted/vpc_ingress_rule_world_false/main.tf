# Fixture: vpc_ingress_rule_world_false
# Expected network_restricted: see directory name (_true|_false|_absent).
terraform {
  required_providers {
    aws = { source = "hashicorp/aws" }
  }
}
provider "aws" { region = "us-east-1" }

resource "aws_security_group" "db" { name = "db"; vpc_id = "vpc-1" }
resource "aws_vpc_security_group_ingress_rule" "open" {
  security_group_id = aws_security_group.db.id
  from_port         = 5432
  to_port           = 5432
  ip_protocol       = "tcp"
  cidr_ipv4         = "0.0.0.0/0"
}
resource "aws_db_instance" "main" {
  identifier = "app"
  engine     = "postgres"
  instance_class = "db.t3.micro"
  vpc_security_group_ids = [aws_security_group.db.id]
}

