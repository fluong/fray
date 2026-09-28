# Fixture root for the aws-web-app shape. Plan only; do not apply.
#
# Planted so the mapped rules have something to catch. The parser does not
# read environment values, only names.
#
# Open:
#   FR-001  ALB is internet-facing and ingress is 0.0.0.0/0, listener has no auth
#   FR-003  DB_PASSWORD is an ECS secret (injected as an environment variable)
#   FR-005  image is a tag, not a digest
#   FR-009  the secret has no rotation resource
#   FR-012  force_destroy is true, so deletion_protection is false.
#           force_destroy = false would count as protection and close FR-012.
#   FR-014  versioning is configured and Suspended
#   FR-026  the public listener is HTTP, so the network crossing is plaintext
# Unverified:
#   FR-023  CloudTrail data events are not in this root, and fray.yaml does not
#           declare audit_config owned_by_this_root, so audit_logging is absent
# Mitigated:
#   FR-002  autoscaling_max_capacity is 10
#   FR-006  Secrets Manager audit logging is the CloudTrail default
#   FR-007  GetSecretValue is granted on this secret's ARN only
#   FR-008  recovery window is left at the provider default (30 days)
#   FR-010  the bucket is not public
#   FR-024  object ownership is BucketOwnerEnforced
#   FR-025  all four Block Public Access flags are true
# Stored, no current rule:
#   RDS deletion_protection, storage_encrypted, publicly_accessible = false
#   S3 SSE-S3 (the encryption sibling is present)

provider "aws" {
  region = "us-east-1"
}

locals {
  name = "fray-aws-web-app"
  azs  = ["us-east-1a", "us-east-1b"]
}

resource "random_password" "db" {
  length  = 16
  special = false
}

module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "6.7.3"

  name = local.name
  cidr = "10.0.0.0/16"
  azs  = local.azs

  public_subnets  = ["10.0.0.0/24", "10.0.1.0/24"]
  private_subnets = ["10.0.10.0/24", "10.0.11.0/24"]

  enable_nat_gateway = true
  single_nat_gateway = true
}

module "alb" {
  source  = "terraform-aws-modules/alb/aws"
  version = "10.5.1"

  name    = local.name
  vpc_id  = module.vpc.vpc_id
  subnets = module.vpc.public_subnets

  internal = false

  security_group_ingress_rules = {
    http = {
      from_port   = 80
      to_port     = 80
      ip_protocol = "tcp"
      cidr_ipv4   = "0.0.0.0/0"
    }
  }
  security_group_egress_rules = {
    to_vpc = {
      ip_protocol = "-1"
      cidr_ipv4   = "10.0.0.0/16"
    }
  }

  # HTTP keeps FR-026 open on the public client → ALB flow. HTTPS would be tls.
  listeners = {
    http = {
      port     = 80
      protocol = "HTTP"
      forward = {
        target_group_key = "app"
      }
    }
  }

  target_groups = {
    app = {
      backend_protocol  = "HTTP"
      backend_port      = 8080
      target_type       = "ip"
      create_attachment = false
    }
  }
}

module "ecs_cluster" {
  source  = "terraform-aws-modules/ecs/aws//modules/cluster"
  version = "7.6.1"

  name = local.name
}

module "ecs_service" {
  source  = "terraform-aws-modules/ecs/aws//modules/service"
  version = "7.6.1"

  name        = local.name
  cluster_arn = module.ecs_cluster.arn

  cpu    = 256
  memory = 512

  # Cap of 10 passes FR-002. The module default is also 10; set it on purpose.
  enable_autoscaling       = true
  autoscaling_max_capacity = 10

  container_definitions = {
    app = {
      essential = true
      image     = "public.ecr.aws/docker/library/nginx:1.27"
      portMappings = [
        {
          containerPort = 8080
          protocol      = "tcp"
        }
      ]
      secrets = [
        {
          name      = "DB_PASSWORD"
          valueFrom = module.db_password.secret_arn
        }
      ]
      # The value is the database address. The parser must not read it.
      environment = [
        {
          name  = "DB_HOST"
          value = module.db.db_instance_address
        }
      ]
    }
  }

  task_exec_secret_arns = [module.db_password.secret_arn]

  tasks_iam_role_statements = [
    {
      sid = "ListBucket"
      actions = [
        "s3:ListBucket",
      ]
      resources = [module.uploads.s3_bucket_arn]
    },
    {
      sid = "WriteObjects"
      actions = [
        "s3:GetObject",
        "s3:PutObject",
        "s3:DeleteObject",
      ]
      resources = ["${module.uploads.s3_bucket_arn}/*"]
    }
  ]

  subnet_ids         = module.vpc.private_subnets
  security_group_ids = [aws_security_group.tasks.id]

  # The module's own security group looks up the subnet. Ours does not.
  create_security_group = false

  load_balancer = {
    app = {
      target_group_arn = module.alb.target_groups["app"].arn
      container_name   = "app"
      container_port   = 8080
    }
  }
}

module "db" {
  source  = "terraform-aws-modules/rds/aws"
  version = "7.2.2"

  identifier = local.name

  engine               = "postgres"
  engine_version       = "16"
  family               = "postgres16"
  major_engine_version = "16"
  instance_class       = "db.t4g.micro"

  allocated_storage = 20
  storage_encrypted = true

  db_name  = "app"
  username = "app"
  port     = 5432

  # Our secret is the one the task reads. Leave RDS-managed rotation off.
  manage_master_user_password = false
  password_wo                 = random_password.db.result
  password_wo_version         = 1

  multi_az               = false
  publicly_accessible    = false
  deletion_protection    = true
  create_db_subnet_group = true
  subnet_ids             = module.vpc.private_subnets
  vpc_security_group_ids = [aws_security_group.db.id]
}

resource "aws_security_group" "tasks" {
  name_prefix = "${local.name}-tasks-"
  vpc_id      = module.vpc.vpc_id

  ingress {
    description     = "App port from the load balancer"
    from_port       = 8080
    to_port         = 8080
    protocol        = "tcp"
    security_groups = [module.alb.security_group_id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "db" {
  name_prefix = "${local.name}-db-"
  vpc_id      = module.vpc.vpc_id

  ingress {
    description     = "Postgres from the task"
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.tasks.id]
  }
}

module "uploads" {
  source  = "terraform-aws-modules/s3-bucket/aws"
  version = "5.16.1"

  bucket_prefix = "${local.name}-uploads-"
  # true so FR-012 stays open. force_destroy = false would be deletion_protection.
  force_destroy = true

  versioning = {
    enabled = false
  }

  control_object_ownership = true
  object_ownership         = "BucketOwnerEnforced"

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true

  server_side_encryption_configuration = {
    rule = {
      apply_server_side_encryption_by_default = {
        sse_algorithm = "AES256"
      }
    }
  }
}

module "db_password" {
  source  = "terraform-aws-modules/secrets-manager/aws"
  version = "2.1.1"

  name          = "${local.name}/db-password"
  description   = "Database password for the web task"
  secret_string = random_password.db.result
}
