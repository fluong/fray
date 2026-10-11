# Fixture: inline_one_block_two_peers_first_apply_true
# One ingress block with two direct peer SGs (ids unknown) → true.
terraform {
  required_providers {
    aws = { source = "hashicorp/aws" }
  }
}
provider "aws" { region = "us-east-1" }

resource "aws_security_group" "app" { name = "app"; vpc_id = "vpc-1" }
resource "aws_security_group" "bastion" { name = "bastion"; vpc_id = "vpc-1" }
resource "aws_security_group" "db" {
  name   = "db"
  vpc_id = "vpc-1"
  ingress {
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.app.id, aws_security_group.bastion.id]
  }
}
resource "aws_db_instance" "main" {
  identifier             = "app"
  engine                 = "postgres"
  instance_class         = "db.t3.micro"
  vpc_security_group_ids = [aws_security_group.db.id]
}
