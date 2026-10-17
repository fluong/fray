resource "aws_dynamodb_resource_policy" "ddb_rp_world" {
  resource_arn = aws_dynamodb_table.ddb_rp_world.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "WorldGetItem"
      Effect    = "Allow"
      Principal = "*"
      Action    = "dynamodb:GetItem"
      Resource  = aws_dynamodb_table.ddb_rp_world.arn
    }]
  })
}

resource "aws_dynamodb_resource_policy" "ddb_rp_foreign" {
  resource_arn = aws_dynamodb_table.ddb_rp_foreign.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "ForeignRoot"
      Effect = "Allow"
      Principal = {
        AWS = "arn:aws:iam::111122223333:root"
      }
      Action   = "dynamodb:GetItem"
      Resource = aws_dynamodb_table.ddb_rp_foreign.arn
    }]
  })
}

resource "aws_dynamodb_resource_policy" "ddb_rp_same" {
  resource_arn = aws_dynamodb_table.ddb_rp_same.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "SamePlanRole"
      Effect = "Allow"
      Principal = {
        AWS = aws_iam_role.b71_reader.arn
      }
      Action   = "dynamodb:GetItem"
      Resource = aws_dynamodb_table.ddb_rp_same.arn
    }]
  })
}

resource "aws_dynamodb_resource_policy" "ddb_rp_org" {
  resource_arn = aws_dynamodb_table.ddb_rp_org.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "OrgRestrictedWorld"
      Effect    = "Allow"
      Principal = "*"
      Action    = "dynamodb:GetItem"
      Resource  = aws_dynamodb_table.ddb_rp_org.arn
      Condition = {
        StringEquals = {
          "aws:PrincipalOrgID" = "o-exampleorgid"
        }
      }
    }]
  })
}

resource "aws_dynamodb_resource_policy" "ddb_rp_deny_cond" {
  resource_arn = aws_dynamodb_table.ddb_rp_deny_cond.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowOrg"
        Effect    = "Allow"
        Principal = "*"
        Action    = "dynamodb:GetItem"
        Resource  = aws_dynamodb_table.ddb_rp_deny_cond.arn
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
        Action    = "dynamodb:*"
        Resource  = aws_dynamodb_table.ddb_rp_deny_cond.arn
        Condition = {
          StringNotEquals = {
            "aws:PrincipalOrgID" = "o-exampleorgid"
          }
        }
      },
    ]
  })
}
