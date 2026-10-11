# Fixture: vpc_ingress_null_optionals_world_false
# aws_vpc_security_group_ingress_rule with ip_protocol + world CIDR.
# Real module for_each plans also null unused optional source fields
# (cidr_ipv6, prefix_list_id, referenced_security_group_id) while still
# listing each.value.* configuration refs — those must not poison classification.
# Expected network_restricted: false
# Before f1e2ed1 null-optional fix: absent (unknown). After: false.
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
  # cidr_ipv6 / prefix_list_id / referenced_security_group_id intentionally unset;
  # terraform plan still emits null for them on this resource type.
}
resource "aws_db_instance" "main" {
  identifier             = "app"
  engine                 = "postgres"
  instance_class         = "db.t3.micro"
  vpc_security_group_ids = [aws_security_group.db.id]
}
