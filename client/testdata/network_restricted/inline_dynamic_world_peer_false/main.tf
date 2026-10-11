# Fixture: inline_dynamic_world_peer_false
# dynamic ingress: one iteration world CIDR, one peer → network_restricted=false
terraform {
  required_providers {
    aws = { source = "hashicorp/aws" }
  }
}
provider "aws" { region = "us-east-1" }

resource "aws_security_group" "app" { name = "app"; vpc_id = "vpc-1" }
resource "aws_security_group" "db" {
  name   = "db"
  vpc_id = "vpc-1"
  dynamic "ingress" {
    for_each = {
      world = { cidr_blocks = ["0.0.0.0/0"], security_groups = [] }
      peer  = { cidr_blocks = [], security_groups = [aws_security_group.app.id] }
    }
    content {
      from_port       = 5432
      to_port         = 5432
      protocol        = "tcp"
      cidr_blocks     = ingress.value.cidr_blocks
      security_groups = ingress.value.security_groups
    }
  }
}
resource "aws_db_instance" "main" {
  identifier             = "app"
  engine                 = "postgres"
  instance_class         = "db.t3.micro"
  vpc_security_group_ids = [aws_security_group.db.id]
}
