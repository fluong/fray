# Fixture: inline dynamic world + peer → public=true
terraform {
  required_providers {
    aws = { source = "hashicorp/aws" }
  }
}
provider "aws" { region = "us-east-1" }

resource "aws_security_group" "app" { name = "app"; vpc_id = "vpc-1" }
resource "aws_security_group" "alb" {
  name   = "alb"
  vpc_id = "vpc-1"
  dynamic "ingress" {
    for_each = {
      world = { cidr_blocks = ["0.0.0.0/0"], security_groups = [] }
      peer  = { cidr_blocks = [], security_groups = [aws_security_group.app.id] }
    }
    content {
      from_port       = 80
      to_port         = 80
      protocol        = "tcp"
      cidr_blocks     = ingress.value.cidr_blocks
      security_groups = ingress.value.security_groups
    }
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
