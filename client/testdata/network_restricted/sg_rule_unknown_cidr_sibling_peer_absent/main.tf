# Fixture: sg_rule_unknown_cidr_sibling_peer_absent
# aws_security_group_rule with cidr_blocks = var.allowed (unknown) plus a
# sibling peer rule. Unknown CIDR ⇒ network_restricted absent.
terraform {
  required_providers {
    aws = { source = "hashicorp/aws" }
  }
}
provider "aws" { region = "us-east-1" }

variable "allowed" { type = list(string) }
resource "aws_security_group" "app" { name = "app"; vpc_id = "vpc-1" }
resource "aws_security_group" "db" { name = "db"; vpc_id = "vpc-1" }
resource "aws_security_group_rule" "cidr" {
  type              = "ingress"
  security_group_id = aws_security_group.db.id
  from_port         = 5432
  to_port           = 5432
  protocol          = "tcp"
  cidr_blocks       = var.allowed
}
resource "aws_security_group_rule" "peer" {
  type                     = "ingress"
  security_group_id        = aws_security_group.db.id
  from_port                = 5432
  to_port                  = 5432
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.app.id
}
resource "aws_db_instance" "main" {
  identifier             = "app"
  engine                 = "postgres"
  instance_class         = "db.t3.micro"
  vpc_security_group_ids = [aws_security_group.db.id]
}
