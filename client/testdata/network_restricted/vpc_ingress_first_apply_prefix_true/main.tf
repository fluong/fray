# Fixture: vpc_ingress_first_apply_prefix_true
# Direct prefix_list_id = managed PL (private entries), id unknown after apply.
# Expected network_restricted: true
terraform {
  required_providers {
    aws = { source = "hashicorp/aws" }
  }
}
provider "aws" { region = "us-east-1" }

resource "aws_ec2_managed_prefix_list" "priv" {
  name           = "priv"
  address_family = "IPv4"
  max_entries    = 1
  entry { cidr = "10.0.0.0/8" }
}
resource "aws_security_group" "db" { name = "db"; vpc_id = "vpc-1" }
resource "aws_vpc_security_group_ingress_rule" "pl" {
  security_group_id = aws_security_group.db.id
  from_port         = 5432
  to_port           = 5432
  ip_protocol       = "tcp"
  prefix_list_id    = aws_ec2_managed_prefix_list.priv.id
}
resource "aws_db_instance" "main" {
  identifier             = "app"
  engine                 = "postgres"
  instance_class         = "db.t3.micro"
  vpc_security_group_ids = [aws_security_group.db.id]
}
