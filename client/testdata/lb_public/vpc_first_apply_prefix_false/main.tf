# Fixture: vpc_first_apply_prefix_false
# Direct private prefix list, id unknown after apply → public=false
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
resource "aws_security_group" "alb" { name = "alb"; vpc_id = "vpc-1" }
resource "aws_vpc_security_group_ingress_rule" "pl" {
  security_group_id = aws_security_group.alb.id
  from_port         = 80
  to_port           = 80
  ip_protocol       = "tcp"
  prefix_list_id    = aws_ec2_managed_prefix_list.priv.id
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
