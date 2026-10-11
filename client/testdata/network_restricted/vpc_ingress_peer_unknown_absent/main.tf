# Fixture: vpc_ingress_peer_unknown_absent
# cidr_ipv4 null; referenced_security_group_id unknown after apply (null in
# plan, config refs aws_security_group.tasks). Must NOT resolve to restricted.
# Expected network_restricted: absent
terraform {
  required_providers {
    aws = { source = "hashicorp/aws" }
  }
}
provider "aws" { region = "us-east-1" }

resource "aws_security_group" "tasks" { name = "tasks"; vpc_id = "vpc-1" }
resource "aws_security_group" "db" { name = "db"; vpc_id = "vpc-1" }
resource "aws_vpc_security_group_ingress_rule" "peer" {
  security_group_id              = aws_security_group.db.id
  from_port                      = 5432
  to_port                        = 5432
  ip_protocol                    = "tcp"
  referenced_security_group_id   = aws_security_group.tasks.id
}
resource "aws_db_instance" "main" {
  identifier             = "app"
  engine                 = "postgres"
  instance_class         = "db.t3.micro"
  vpc_security_group_ids = [aws_security_group.db.id]
}
