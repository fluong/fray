# Fixture: cross_module_sg_world — LB in module, SG in root with world ingress on :80.
# Expected public: true
terraform {
  required_providers {
    aws = { source = "hashicorp/aws" }
  }
}
provider "aws" { region = "us-east-1" }

resource "aws_security_group" "alb" {
  name   = "alb"
  vpc_id = "vpc-1"
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

module "alb" {
  source          = "./modules/alb"
  security_groups = [aws_security_group.alb.id]
}
