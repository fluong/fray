# Fixture: unresolvable_absent
# Expected network_restricted: see directory name (_true|_false|_absent).
terraform {
  required_providers {
    aws = { source = "hashicorp/aws" }
  }
}
provider "aws" { region = "us-east-1" }

resource "aws_db_instance" "main" {
  identifier = "app"
  engine     = "postgres"
  instance_class = "db.t3.micro"
}

