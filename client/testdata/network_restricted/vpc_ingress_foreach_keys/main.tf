# Fixture: vpc_ingress_foreach_keys
# for_each: "http" → cidr world; "db" → peer SG. Shared each.value.* config must
# not cross-contaminate instances (classify from planned values per instance).
terraform {
  required_providers {
    aws = { source = "hashicorp/aws" }
  }
}
provider "aws" { region = "us-east-1" }

resource "aws_security_group" "app" { name = "app"; vpc_id = "vpc-1" }
resource "aws_security_group" "db" { name = "db"; vpc_id = "vpc-1" }

locals {
  rules = {
    http = { cidr_ipv4 = "0.0.0.0/0", referenced_security_group_id = null }
    db   = { cidr_ipv4 = null, referenced_security_group_id = aws_security_group.app.id }
  }
}

resource "aws_vpc_security_group_ingress_rule" "this" {
  for_each                     = local.rules
  security_group_id            = aws_security_group.db.id
  from_port                    = 5432
  to_port                      = 5432
  ip_protocol                  = "tcp"
  cidr_ipv4                    = each.value.cidr_ipv4
  referenced_security_group_id = each.value.referenced_security_group_id
}

resource "aws_db_instance" "main" {
  identifier             = "app"
  engine                 = "postgres"
  instance_class         = "db.t3.micro"
  vpc_security_group_ids = [aws_security_group.db.id]
}
