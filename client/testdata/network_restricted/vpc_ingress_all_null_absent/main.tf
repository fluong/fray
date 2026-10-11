# Fixture: vpc_ingress_all_null_absent
# Degenerate: every source field null (for_each each.value.* refs only).
# Rule contributes no resolved source → unknown; cannot yield restricted=true.
# Expected network_restricted: absent
terraform {
  required_providers {
    aws = { source = "hashicorp/aws" }
  }
}
provider "aws" { region = "us-east-1" }

resource "aws_security_group" "db" { name = "db"; vpc_id = "vpc-1" }
# No ingress rule resource with concrete sources — unit test synthesizes
# an all-null aws_vpc_security_group_ingress_rule. This file documents the
# empty-source outcome for the SG association alone (also absent without rules
# that resolve).
resource "aws_db_instance" "main" {
  identifier             = "app"
  engine                 = "postgres"
  instance_class         = "db.t3.micro"
  vpc_security_group_ids = [aws_security_group.db.id]
}
