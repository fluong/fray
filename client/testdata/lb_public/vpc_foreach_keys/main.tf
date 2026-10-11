# Fixture: vpc_foreach_keys — for_each http=world, db=peer (per-instance values).
terraform {
  required_providers {
    aws = { source = "hashicorp/aws" }
  }
}
provider "aws" { region = "us-east-1" }

resource "aws_security_group" "app" { name = "app"; vpc_id = "vpc-1" }
resource "aws_security_group" "alb" { name = "alb"; vpc_id = "vpc-1" }
locals {
  rules = {
    http = { cidr_ipv4 = "0.0.0.0/0", referenced_security_group_id = null }
    db   = { cidr_ipv4 = null, referenced_security_group_id = aws_security_group.app.id }
  }
}
resource "aws_vpc_security_group_ingress_rule" "this" {
  for_each                     = local.rules
  security_group_id            = aws_security_group.alb.id
  from_port                    = 80
  to_port                      = 80
  ip_protocol                  = "tcp"
  cidr_ipv4                    = each.value.cidr_ipv4
  referenced_security_group_id = each.value.referenced_security_group_id
}
resource "aws_lb" "main" {
  name               = "alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = ["subnet-1", "subnet-2"]
}
resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.main.arn
  port              = 80
  protocol          = "HTTP"
  default_action {
    type = "fixed-response"
    fixed_response {
      content_type = "text/plain"
      message_body = "ok"
      status_code  = "200"
    }
  }
}
