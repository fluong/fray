# Expected audit_logging: true (all-buckets arn:aws:s3)
terraform {
  required_providers {
    aws = { source = "hashicorp/aws" }
  }
}
provider "aws" { region = "us-east-1" }

resource "aws_s3_bucket" "app" { bucket = "app-data" }
resource "aws_s3_bucket" "trail" { bucket = "trail-logs" }
resource "aws_cloudtrail" "main" {
  name           = "main"
  s3_bucket_name = aws_s3_bucket.trail.id
  event_selector {
    read_write_type           = "All"
    include_management_events = false
    data_resource {
      type   = "AWS::S3::Object"
      values = ["arn:aws:s3"]
    }
  }
}
