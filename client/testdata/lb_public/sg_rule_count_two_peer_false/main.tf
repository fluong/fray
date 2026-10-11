# Fixture: sg_rule_count_two_peer_false
# aws_security_group_rule count=2, direct peer (ids unknown) → public false.
terraform {
  required_providers {
    aws = { source = "hashicorp/aws" }
  }
}
provider "aws" { region = "us-east-1" }

resource "aws_security_group" "app" { name = "app"; vpc_id = "vpc-1" }
resource "aws_security_group" "alb" { name = "alb"; vpc_id = "vpc-1" }
resource "aws_security_group_rule" "peer" {
  count                    = 2
  type                     = "ingress"
  from_port                = 80
  to_port                  = 80
  protocol                 = "tcp"
  security_group_id        = aws_security_group.alb.id
  source_security_group_id = aws_security_group.app.id
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
