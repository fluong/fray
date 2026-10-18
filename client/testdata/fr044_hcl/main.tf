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

resource "aws_sqs_queue" "sqs_rp_world" {
  name = "fray-coverage-sqs-rp-world-fake"
}

resource "aws_sqs_queue_policy" "sqs_rp_world" {
  queue_url = aws_sqs_queue.sqs_rp_world.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "WorldSend"
      Effect    = "Allow"
      Principal = "*"
      Action    = "sqs:SendMessage"
      Resource  = aws_sqs_queue.sqs_rp_world.arn
    }]
  })
}

resource "aws_sqs_queue" "sqs_rp_foreign" {
  name = "fray-coverage-sqs-rp-foreign-fake"
}

resource "aws_sqs_queue_policy" "sqs_rp_foreign" {
  queue_url = aws_sqs_queue.sqs_rp_foreign.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "ForeignRoot"
      Effect = "Allow"
      Principal = {
        AWS = "arn:aws:iam::444455556666:root"
      }
      Action   = "sqs:SendMessage"
      Resource = aws_sqs_queue.sqs_rp_foreign.arn
    }]
  })
}

resource "aws_sqs_queue" "sqs_rp_same" {
  name = "fray-coverage-sqs-rp-same-fake"
}

resource "aws_sqs_queue_policy" "sqs_rp_same" {
  queue_url = aws_sqs_queue.sqs_rp_same.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "SamePlanRole"
      Effect = "Allow"
      Principal = {
        AWS = aws_iam_role.b71_reader.arn
      }
      Action   = "sqs:SendMessage"
      Resource = aws_sqs_queue.sqs_rp_same.arn
    }]
  })
}

resource "aws_sqs_queue" "sqs_rp_org" {
  name = "fray-coverage-sqs-rp-org-fake"
}

resource "aws_sqs_queue_policy" "sqs_rp_org" {
  queue_url = aws_sqs_queue.sqs_rp_org.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "OrgRestrictedWorld"
      Effect    = "Allow"
      Principal = "*"
      Action    = "sqs:SendMessage"
      Resource  = aws_sqs_queue.sqs_rp_org.arn
      Condition = {
        StringEquals = {
          "aws:PrincipalOrgID" = "o-exampleorgid"
        }
      }
    }]
  })
}

resource "aws_sqs_queue" "sqs_rp_deny_cond" {
  name = "fray-coverage-sqs-rp-deny-cond-fake"
}

resource "aws_sqs_queue_policy" "sqs_rp_deny_cond" {
  queue_url = aws_sqs_queue.sqs_rp_deny_cond.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowOrg"
        Effect    = "Allow"
        Principal = "*"
        Action    = "sqs:SendMessage"
        Resource  = aws_sqs_queue.sqs_rp_deny_cond.arn
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
        Action    = "sqs:*"
        Resource  = aws_sqs_queue.sqs_rp_deny_cond.arn
        Condition = {
          StringNotEquals = {
            "aws:PrincipalOrgID" = "o-exampleorgid"
          }
        }
      },
    ]
  })
}

resource "aws_sqs_queue" "sqs_rp_doc" {
  name = "fray-coverage-sqs-rp-doc-fake"
}

data "aws_iam_policy_document" "sqs_rp_doc" {
  statement {
    sid    = "SourceVpceRestricted"
    effect = "Allow"
    actions = [
      "sqs:SendMessage",
    ]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    resources = [
      aws_sqs_queue.sqs_rp_doc.arn,
    ]
    condition {
      test     = "StringEquals"
      variable = "aws:SourceVpce"
      values   = ["vpce-0123456789abcdef0"]
    }
  }
}

resource "aws_sqs_queue_policy" "sqs_rp_doc" {
  queue_url = aws_sqs_queue.sqs_rp_doc.id
  policy    = data.aws_iam_policy_document.sqs_rp_doc.json
}

resource "aws_sqs_queue" "sqs_rp_none" {
  name = "fray-coverage-sqs-rp-none-fake"
}

resource "aws_sns_topic" "sns_rp_world" {
  name = "fray-coverage-sns-rp-world-fake"
}

resource "aws_sns_topic_policy" "sns_rp_world" {
  arn = aws_sns_topic.sns_rp_world.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "WorldPublish"
      Effect    = "Allow"
      Principal = "*"
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.sns_rp_world.arn
    }]
  })
}

resource "aws_sns_topic" "sns_rp_default" {
  name = "fray-coverage-sns-rp-default-fake"
}

resource "aws_sns_topic" "sns_rp_owner" {
  name = "fray-coverage-sns-rp-owner-fake"
}

resource "aws_sns_topic_policy" "sns_rp_owner" {
  arn = aws_sns_topic.sns_rp_owner.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "SourceOwnerStar"
      Effect    = "Allow"
      Principal = "*"
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.sns_rp_owner.arn
      Condition = {
        StringEquals = {
          "AWS:SourceOwner" = "111122223333"
        }
      }
    }]
  })
}

# F45-RES: scoped SQS + SNS on a dedicated Lambda (same packaging as b71_reader).
resource "aws_iam_role" "f45_res" {
  name               = "fray-coverage-f45-res"
  assume_role_policy = local.assume_lambda
}

resource "aws_iam_role_policy" "f45_res" {
  name = "f45-res-queues"
  role = aws_iam_role.f45_res.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "SendOneQueue"
        Effect   = "Allow"
        Action   = ["sqs:SendMessage"]
        Resource = [aws_sqs_queue.sqs_rp_none.arn]
      },
      {
        Sid      = "PublishDefaultTopic"
        Effect   = "Allow"
        Action   = ["sns:Publish"]
        Resource = [aws_sns_topic.sns_rp_default.arn]
      },
    ]
  })
}

resource "aws_lambda_function" "f45_res" {
  function_name = "fray-coverage-f45-res"
  role          = aws_iam_role.f45_res.arn
  handler       = "index.handler"
  runtime       = "nodejs20.x"
  filename      = "${path.module}/lambda_placeholder.zip"
}

# F45-ACC: account-wide SQS on a dedicated Lambda.
resource "aws_iam_role" "f45_acc" {
  name               = "fray-coverage-f45-acc"
  assume_role_policy = local.assume_lambda
}

resource "aws_iam_role_policy" "f45_acc" {
  name = "f45-acc-sqs"
  role = aws_iam_role.f45_acc.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "AllSQS"
      Effect   = "Allow"
      Action   = ["sqs:*"]
      Resource = ["*"]
    }]
  })
}

resource "aws_lambda_function" "f45_acc" {
  function_name = "fray-coverage-f45-acc"
  role          = aws_iam_role.f45_acc.arn
  handler       = "index.handler"
  runtime       = "nodejs20.x"
  filename      = "${path.module}/lambda_placeholder.zip"
}
