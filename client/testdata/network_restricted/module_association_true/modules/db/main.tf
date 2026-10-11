variable "vpc_security_group_ids" { type = list(string) }
resource "aws_db_instance" "this" {
  identifier             = "app"
  engine                 = "postgres"
  instance_class         = "db.t3.micro"
  vpc_security_group_ids = var.vpc_security_group_ids
}
