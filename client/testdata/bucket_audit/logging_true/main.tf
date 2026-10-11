# Expected audit_logging: true (aws_s3_bucket_logging)
terraform {
  required_providers {
    aws = { source = "hashicorp/aws" }
  }
}
provider "aws" { region = "us-east-1" }

resource "aws_s3_bucket" "app" { bucket = "app-data" }
resource "aws_s3_bucket" "logs" { bucket = "app-logs" }
resource "aws_s3_bucket_logging" "app" {
  bucket        = aws_s3_bucket.app.id
  target_bucket = aws_s3_bucket.logs.id
  target_prefix = "access/"
}
