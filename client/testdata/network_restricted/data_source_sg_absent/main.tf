# Fixture: data_source_sg_absent
# Expected network_restricted: see directory name (_true|_false|_absent).
terraform {
  required_providers {
    aws = { source = "hashicorp/aws" }
  }
}
provider "aws" { region = "us-east-1" }

data "aws_security_group" "shared" { id = "sg-shared" }
resource "aws_db_instance" "main" {
  identifier = "app"
  engine     = "postgres"
  instance_class = "db.t3.micro"
  vpc_security_group_ids = [data.aws_security_group.shared.id]
}

