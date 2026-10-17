resource "aws_iam_role_policy" "b72_jsonencode" {
  name = "b72-jsonencode-s3"
  role = aws_iam_role.b72_jsonencode.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:GetObject"]
      Resource = "${aws_s3_bucket.b72_jsonencode.arn}/*"
    }]
  })
}

resource "aws_iam_role_policy" "b72_local" {
  name = "b72-local-s3"
  role = aws_iam_role.b72_local.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:GetObject"]
      Resource = local.b72_local_resource
    }]
  })
}
