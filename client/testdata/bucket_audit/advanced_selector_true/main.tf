# Expected audit_logging: true (advanced_event_selector)
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
  advanced_event_selector {
    name = "s3-app"
    field_selector {
      field  = "eventCategory"
      equals = ["Data"]
    }
    field_selector {
      field  = "resources.type"
      equals = ["AWS::S3::Object"]
    }
    field_selector {
      field        = "resources.ARN"
      starts_with  = ["${aws_s3_bucket.app.arn}/"]
    }
  }
}
