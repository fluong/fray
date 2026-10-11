# Fixture: inline_two_peer_blocks_first_apply_false
# Two static peer ingress blocks on listener port (ids unknown) → public false.
terraform {
  required_providers {
    aws = { source = "hashicorp/aws" }
  }
}
provider "aws" { region = "us-east-1" }

resource "aws_security_group" "app" { name = "app"; vpc_id = "vpc-1" }
resource "aws_security_group" "bastion" { name = "bastion"; vpc_id = "vpc-1" }
resource "aws_security_group" "alb" {
  name   = "alb"
  vpc_id = "vpc-1"
  ingress {
    from_port       = 80
    to_port         = 80
    protocol        = "tcp"
    security_groups = [aws_security_group.app.id]
  }
  ingress {
    from_port       = 80
    to_port         = 80
    protocol        = "tcp"
    security_groups = [aws_security_group.bastion.id]
  }
}
resource "aws_lb" "main" {
  name               = "alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
}
resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.main.arn
  port              = 80
  protocol          = "HTTP"
  default_action { type = "fixed-response"
    fixed_response { content_type = "text/plain"; message_body = "ok"; status_code = "200" }
  }
}
