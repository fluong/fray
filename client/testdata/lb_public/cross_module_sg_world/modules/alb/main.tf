variable "security_groups" { type = list(string) }

resource "aws_lb" "this" {
  name               = "alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = var.security_groups
  subnets            = ["subnet-1", "subnet-2"]
}

resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.this.arn
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
