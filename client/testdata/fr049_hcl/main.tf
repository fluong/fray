locals {
  assume_lambda = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role" "b71_reader" {
  name               = "fray-coverage-b71-reader"
  assume_role_policy = local.assume_lambda
}

# (m) S3 bucket policies + Secrets Manager resource policies (Action v0.37.0+
# for FR-049 / FR-050). Separate buckets/secrets from B-71 uploads and app
# secret. No IAM flows to these resources on the v0.36.0 pin.
# S-K–S-O, S-BPA: aws_s3_bucket_policy (parser links at v0.37.0+).
# S-INLINE skipped: AWS provider ~> 6.0 has no `policy` on aws_s3_bucket.
# SM-*: aws_secretsmanager_secret_policy (+ block_public_policy on SM-BPP).
# ---------------------------------------------------------------------------

resource "aws_s3_bucket" "s3_rp_world" {
  bucket = "fray-coverage-s3-rp-world-fake"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "s3_rp_world" {
  bucket = aws_s3_bucket.s3_rp_world.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_policy" "s3_rp_world" {
  bucket = aws_s3_bucket.s3_rp_world.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "WorldGetObject"
      Effect    = "Allow"
      Principal = "*"
      Action    = "s3:GetObject"
      Resource  = "${aws_s3_bucket.s3_rp_world.arn}/*"
    }]
  })
}

resource "aws_s3_bucket" "s3_rp_foreign" {
  bucket = "fray-coverage-s3-rp-foreign-fake"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "s3_rp_foreign" {
  bucket = aws_s3_bucket.s3_rp_foreign.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_policy" "s3_rp_foreign" {
  bucket = aws_s3_bucket.s3_rp_foreign.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "ForeignRoot"
      Effect = "Allow"
      Principal = {
        AWS = "arn:aws:iam::111122223333:root"
      }
      Action   = "s3:GetObject"
      Resource = "${aws_s3_bucket.s3_rp_foreign.arn}/*"
    }]
  })
}

resource "aws_s3_bucket" "s3_rp_same" {
  bucket = "fray-coverage-s3-rp-same-fake"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "s3_rp_same" {
  bucket = aws_s3_bucket.s3_rp_same.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_policy" "s3_rp_same" {
  bucket = aws_s3_bucket.s3_rp_same.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "SamePlanRole"
      Effect = "Allow"
      Principal = {
        AWS = aws_iam_role.b71_reader.arn
      }
      Action   = "s3:GetObject"
      Resource = "${aws_s3_bucket.s3_rp_same.arn}/*"
    }]
  })
}

resource "aws_s3_bucket" "s3_rp_org" {
  bucket = "fray-coverage-s3-rp-org-fake"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "s3_rp_org" {
  bucket = aws_s3_bucket.s3_rp_org.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_policy" "s3_rp_org" {
  bucket = aws_s3_bucket.s3_rp_org.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "OrgRestrictedWorld"
      Effect    = "Allow"
      Principal = "*"
      Action    = "s3:GetObject"
      Resource  = "${aws_s3_bucket.s3_rp_org.arn}/*"
      Condition = {
        StringEquals = {
          "aws:PrincipalOrgID" = "o-exampleorgid"
        }
      }
    }]
  })
}

resource "aws_s3_bucket" "s3_rp_deny_cond" {
  bucket = "fray-coverage-s3-rp-deny-cond-fake"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "s3_rp_deny_cond" {
  bucket = aws_s3_bucket.s3_rp_deny_cond.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_policy" "s3_rp_deny_cond" {
  bucket = aws_s3_bucket.s3_rp_deny_cond.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowOrg"
        Effect    = "Allow"
        Principal = "*"
        Action    = "s3:GetObject"
        Resource  = "${aws_s3_bucket.s3_rp_deny_cond.arn}/*"
        Condition = {
          StringEquals = {
            "aws:PrincipalOrgID" = "o-exampleorgid"
          }
        }
      },
      {
        Sid       = "DenyOtherOrg"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource  = [
          aws_s3_bucket.s3_rp_deny_cond.arn,
          "${aws_s3_bucket.s3_rp_deny_cond.arn}/*",
        ]
        Condition = {
          StringNotEquals = {
            "aws:PrincipalOrgID" = "o-exampleorgid"
          }
        }
      },
    ]
  })
}

resource "aws_s3_bucket" "s3_rp_doc" {
  bucket = "fray-coverage-s3-rp-doc-fake"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "s3_rp_doc" {
  bucket = aws_s3_bucket.s3_rp_doc.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

data "aws_iam_policy_document" "s3_rp_doc" {
  statement {
    sid    = "SourceVpceRestricted"
    effect = "Allow"
    actions = [
      "s3:GetObject",
    ]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    resources = [
      "${aws_s3_bucket.s3_rp_doc.arn}/*",
    ]
    condition {
      test     = "StringEquals"
      variable = "aws:SourceVpce"
      values   = ["vpce-0123456789abcdef0"]
    }
  }
}

resource "aws_s3_bucket_policy" "s3_rp_doc" {
  bucket = aws_s3_bucket.s3_rp_doc.id
  policy = data.aws_iam_policy_document.s3_rp_doc.json
}

resource "aws_s3_bucket" "s3_rp_bpa" {
  bucket = "fray-coverage-s3-rp-bpa-fake"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "s3_rp_bpa" {
  bucket = aws_s3_bucket.s3_rp_bpa.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_policy" "s3_rp_bpa" {
  bucket = aws_s3_bucket.s3_rp_bpa.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "WorldGetObjectBlockedByBpa"
      Effect    = "Allow"
      Principal = "*"
      Action    = "s3:GetObject"
      Resource  = "${aws_s3_bucket.s3_rp_bpa.arn}/*"
    }]
  })
}

resource "aws_s3_bucket_public_access_block" "s3_rp_bpa" {
  bucket = aws_s3_bucket.s3_rp_bpa.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_secretsmanager_secret" "sm_rp_world" {
  name = "fray-coverage-sm-rp-world-fake"
}

resource "aws_secretsmanager_secret_policy" "sm_rp_world" {
  secret_arn = aws_secretsmanager_secret.sm_rp_world.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "WorldGetSecretValue"
      Effect    = "Allow"
      Principal = "*"
      Action    = "secretsmanager:GetSecretValue"
      Resource  = aws_secretsmanager_secret.sm_rp_world.arn
    }]
  })
}

resource "aws_secretsmanager_secret" "sm_rp_block" {
  name = "fray-coverage-sm-rp-block-fake"
}

resource "aws_secretsmanager_secret_policy" "sm_rp_block" {
  secret_arn            = aws_secretsmanager_secret.sm_rp_block.arn
  block_public_policy   = true
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "WorldGetSecretValueBlocked"
      Effect    = "Allow"
      Principal = "*"
      Action    = "secretsmanager:GetSecretValue"
      Resource  = aws_secretsmanager_secret.sm_rp_block.arn
    }]
  })
}

resource "aws_secretsmanager_secret" "sm_rp_same" {
  name = "fray-coverage-sm-rp-same-fake"
}

resource "aws_secretsmanager_secret_policy" "sm_rp_same" {
  secret_arn = aws_secretsmanager_secret.sm_rp_same.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "SamePlanRole"
      Effect = "Allow"
      Principal = {
        AWS = aws_iam_role.b71_reader.arn
      }
      Action   = "secretsmanager:GetSecretValue"
      Resource = aws_secretsmanager_secret.sm_rp_same.arn
    }]
  })
}

resource "aws_secretsmanager_secret" "sm_rp_none" {
  name = "fray-coverage-sm-rp-none-fake"
}