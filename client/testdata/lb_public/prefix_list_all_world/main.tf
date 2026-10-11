# Fixture: prefix_list_all_world — managed prefix list with 0.0.0.0/0 on :80.
# Expected public: true
terraform {
  required_providers {
    aws = { source = "hashicorp/aws" }
  }
}
provider "aws" { region = "us-east-1" }

resource "aws_ec2_managed_prefix_list" "world" {
  name           = "world"
  address_family = "IPv4"
  max_entries    = 1
  entry { cidr = "0.0.0.0/0" }
}
resource "aws_security_group" "alb" {
  name   = "alb"
  vpc_id = "vpc-1"
  ingress {
    from_port       = 80
    to_port         = 80
    protocol        = "tcp"
    prefix_list_ids = [aws_ec2_managed_prefix_list.world.id]
  }
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
