# Fixture: unknown_cidr_absent
# Expected network_restricted: see directory name (_true|_false|_absent).
terraform {
  required_providers {
    aws = { source = "hashicorp/aws" }
  }
}
provider "aws" { region = "us-east-1" }

variable "cidrs" { type = list(string) }
resource "aws_security_group" "db" {
  name   = "db"
  vpc_id = "vpc-1"
  ingress {
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = var.cidrs
  }
}
resource "aws_db_instance" "main" {
  identifier = "app"
  engine     = "postgres"
  instance_class = "db.t3.micro"
  vpc_security_group_ids = [aws_security_group.db.id]
}

