terraform {
  required_version = "~> 1.5"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# You run terraform locally after already having
# assumed a role with appropriate permissions.
provider "aws" {
  region = "us-east-2"
}

data "aws_caller_identity" "this" {}
data "aws_region" "this" {}
data "aws_availability_zones" "available" {}


locals {
  name    = "hcdb"
  region  = data.aws_region.this.name

  account_arn        = "arn:aws:iam::${local.account_id}:root"
  account_id         = data.aws_caller_identity.this.account_id

  vpc_cidr = "10.0.0.0/16"
  azs      = slice(data.aws_availability_zones.available.names, 0, 2)

  tags = {
    Repository = "jira-demo-steampipe-and-cloudquery"
    DoNotNuke = "True"
    Permanent = "True"
  }
}

# The password for both steampipe and the hcdb user in RDS. But the hcdb user
# will be converted to an IAM role by the ec2 bootstrap script, bootstrap.sh. So the RDS
# hcdb password won't work for you on RDS after the tf apply is done.
resource "random_password" "master_password" {
  length  = 16
  override_special = "+-?_" # rds is picky about specials
  min_lower=1
  min_upper=1
  min_numeric=1
  min_special=1
}

# RDS database to host the cloudquery database, cq. It is internet
# addressable. It is only accessible via IAM and RDS tokens. The ec2 server role
# has access to it for the ec2 boostrap script to setup the databases and roles
module "db" {
  source = "terraform-aws-modules/rds/aws"

  identifier = format("%s-rds",local.name)

  # All available versions: https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/CHAP_PostgreSQL.html#PostgreSQL.Concepts
  engine               = "postgres"
  engine_version       = "15"
  family               = "postgres15" # DB parameter group
  major_engine_version = "15"         # DB option group
  instance_class       = "db.t4g.large"

  allocated_storage     = 5
  max_allocated_storage = 100

  # NOTE: Do NOT use 'user' as the value for 'username' as it throws:
  # "Error creating DB Instance: InvalidParameterValue: MasterUsername
  # user cannot be used as it is a reserved word used by the engine"
  db_name  = local.name
  username = local.name
  password = random_password.master_password.result
  port     = 5432

  publicly_accessible = true

  manage_master_user_password = false

  iam_database_authentication_enabled = true


  multi_az               = false
  db_subnet_group_name   = module.vpc.database_subnet_group
  vpc_security_group_ids = [aws_security_group.db_security_group.id]

  maintenance_window              = "Mon:00:00-Mon:03:00"
  backup_window                   = "03:00-06:00"
  enabled_cloudwatch_logs_exports = ["postgresql", "upgrade"]
  create_cloudwatch_log_group     = false

  backup_retention_period = 1
  skip_final_snapshot     = true
  deletion_protection     = false

  performance_insights_enabled          = true
  performance_insights_retention_period = 7
  create_monitoring_role                = true
  monitoring_interval                   = 60
  monitoring_role_name                  = format("@%s-mon-role",local.name)
  monitoring_role_use_name_prefix       = true
  monitoring_role_description           = "Monitoring role for rds used for steampipe and cloudquery"

  parameters = [
    {
      name  = "autovacuum"
      value = 1
    },
    {
      name  = "client_encoding"
      value = "utf8"
    }
  ]

  tags = local.tags
  db_option_group_tags = {
    "Sensitive" = "low"
  }
  db_parameter_group_tags = {
    "Sensitive" = "low"
  }
}

resource "aws_secretsmanager_secret" "hcdb_master_pass" {
    description = "username & password for the hcdb postgres db"
    recovery_window_in_days = 0 # force delete on tf destroy
    name = "hcdb_secrets"
    tags = {
      DoNotNuke = "True"
      Permanent = "True"
    }
}

resource "aws_secretsmanager_secret_version" "hcdb_secret_version" {
  secret_id = aws_secretsmanager_secret.hcdb_master_pass.id
  secret_string = jsonencode({
    hcdb_user = local.name
    hcdb_pass = random_password.master_password.result
  })
}



################################################################################
# Supporting Resources
################################################################################

module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "~> 5.0"

  name = format("%s-vpc1",local.name)
  cidr = local.vpc_cidr

  azs              = local.azs

  public_subnet_names  = [for k, v in local.azs : format("%s-subnet-pub-%s",local.name,v)]
  database_subnet_names  = [for k, v in local.azs : format("%s-subnet-db-%s",local.name,v)]

  public_subnets   = [for k, v in local.azs : cidrsubnet(local.vpc_cidr, 8, k)]
  database_subnets = [for k, v in local.azs : cidrsubnet(local.vpc_cidr, 8, k + 3)]

  enable_nat_gateway = false
  single_nat_gateway = false
  one_nat_gateway_per_az = false


  create_database_subnet_group           = true
  create_database_subnet_route_table     = true
  create_database_internet_gateway_route = true

  enable_dns_hostnames = true
  enable_dns_support   = true

  igw_tags = {
    Name = "hcdp-igw1"
  }

  tags = local.tags
}


resource "aws_security_group"  "db_security_group" {
  name = format("%s-db",local.name)
  description = "postgres access for hcdb"
  vpc_id      = module.vpc.vpc_id
  tags = local.tags
}

resource "aws_vpc_security_group_ingress_rule" "allow_pgsql" {
  description = "allow inbound postgres"
  security_group_id = aws_security_group.db_security_group.id
  ip_protocol       = "tcp"
  from_port         = 5432
  to_port           = 5432
  cidr_ipv4 = "0.0.0.0/0"
}


module "ec2_instance" {
  source  = "terraform-aws-modules/ec2-instance/aws"

  depends_on = [ module.db ]

  name = format("%s-svr1",local.name)
  ami_ssm_parameter	= "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"

  instance_type          = "t2.medium"
#  key_name               = "jimkey"
  monitoring             = true
  vpc_security_group_ids = [aws_security_group.ec2_security_group.id]
  subnet_id              = module.vpc.public_subnets[0]

  associate_public_ip_address	= true

  user_data = file("bootstrap.sh")

  iam_instance_profile	= aws_iam_instance_profile.clddbsrv_profile.name # name, not arn or ID

  tags = local.tags
}


resource "aws_security_group"  "ec2_security_group" {
  name = format("%s-ec2",local.name)
  description = "steampipe access for hcdb"
  vpc_id      = module.vpc.vpc_id
  tags = local.tags
}

resource "aws_vpc_security_group_ingress_rule" "allow_ssh" {
  description = "allow inbound ssh"
  security_group_id = aws_security_group.ec2_security_group.id
  ip_protocol       = "tcp"
  from_port         = 22
  to_port           = 22
  cidr_ipv4 = "0.0.0.0/0"
}

resource "aws_vpc_security_group_ingress_rule" "allow_https" {
  description = "allow inbound HTTPS"
  security_group_id = aws_security_group.ec2_security_group.id
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
  cidr_ipv4 = "0.0.0.0/0"
}


resource "aws_vpc_security_group_ingress_rule" "allow_steampipe" {
  description = "allow inbound steampipe" 
  security_group_id = aws_security_group.ec2_security_group.id
  ip_protocol       = "tcp"
  from_port         = 9193
  to_port           = 9193
  cidr_ipv4 = "0.0.0.0/0"
}

resource "aws_vpc_security_group_egress_rule" "allow_internet_access" {
  description = "allow outbound internet" 
  security_group_id = aws_security_group.ec2_security_group.id
  ip_protocol       = "-1"
  cidr_ipv4 = "0.0.0.0/0"
}

resource "aws_iam_instance_profile" "clddbsrv_profile" {
  name = "hcdb_srv_profile"
  role = aws_iam_role.clouddb_svr_role.name
  tags = local.tags
}

resource "aws_iam_role" "clouddb_svr_role" {
  name               = "@hcdb_svr_role"

  # attach inance core role to allow this host to be a bastion host to the RDS instance
  managed_policy_arns = ["arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"]

  assume_role_policy = jsonencode({
      "Version": "2012-10-17",
      "Statement": [
          {
              "Effect": "Allow",
              "Principal": {
                  "Service": "ec2.amazonaws.com"
              },
              "Action": "sts:AssumeRole"
          }
      ]
  })

  inline_policy {
    name = "AllowDescribeRdsInstances"

    policy = jsonencode({
      "Version": "2012-10-17",
      "Statement": [
        {
            "Effect": "Allow",
            "Action": "rds:DescribeDBInstances",
            "Resource": "*"
        }
      ]
    })
  }
  inline_policy {
    name = "AllowAssumeAuditRoles"

    policy = jsonencode({
      "Version": "2012-10-17",
      "Statement": [
        {
            "Effect": "Allow",
            "Action": "sts:AssumeRole",
            "Resource": "arn:aws:iam::*:role/@audit_role"
        }
      ]
    })
  }

  inline_policy {
    name = "AllowManageHcdbSecret"

    policy = jsonencode({
      "Version": "2012-10-17",
      "Statement": [
          {
              "Effect": "Allow",
              "Action": [
                  "secretsmanager:*"
              ],
              "Resource": [
                  "arn:aws:secretsmanager:us-east-2:${data.aws_caller_identity.this.account_id}:secret:hcdb_secrets*"
              ]
          }
      ]
    })
  }

  inline_policy {
    name = "HcdbRdsAuth"

    policy = jsonencode({
      "Version": "2012-10-17",
      "Statement": [
        {
          "Sid": "RdsEc2Auth",
          "Action": [
            "rds-db:connect"
          ],
          "Effect": "Allow",
          "Resource": [
            "arn:aws:rds-db:us-east-2:${data.aws_caller_identity.this.account_id}:dbuser:${module.db.db_instance_resource_id}/cqwrite",
            "arn:aws:rds-db:us-east-2:${data.aws_caller_identity.this.account_id}:dbuser:${module.db.db_instance_resource_id}/cqread",
            "arn:aws:rds-db:us-east-2:${data.aws_caller_identity.this.account_id}:dbuser:${module.db.db_instance_resource_id}/hcdb"
          ]
        }
      ]
    })
  }

  tags = local.tags
}



resource "aws_vpc_endpoint" "ssm" {
  vpc_id            = module.vpc.vpc_id
  service_name      = "com.amazonaws.us-east-2.ssm"
  vpc_endpoint_type = "Interface"
  subnet_ids = module.vpc.public_subnets

  security_group_ids = [
    aws_security_group.ec2_security_group.id
  ]

  private_dns_enabled = true

}

resource "aws_vpc_endpoint" "ec2" {
  vpc_id            = module.vpc.vpc_id
  service_name      = "com.amazonaws.us-east-2.ec2"
  vpc_endpoint_type = "Interface"
  subnet_ids = module.vpc.public_subnets

  security_group_ids = [
    aws_security_group.ec2_security_group.id
  ]

  private_dns_enabled = true
}

resource "aws_vpc_endpoint" "ec2messages" {
  vpc_id            = module.vpc.vpc_id
  service_name      = "com.amazonaws.us-east-2.ec2messages"
  vpc_endpoint_type = "Interface"
  subnet_ids = module.vpc.public_subnets

  security_group_ids = [
    aws_security_group.ec2_security_group.id
  ]

  private_dns_enabled = true
}


resource "aws_vpc_endpoint" "ssmmessages" {
  vpc_id            = module.vpc.vpc_id
  service_name      = "com.amazonaws.us-east-2.ssmmessages"
  vpc_endpoint_type = "Interface"
  subnet_ids = module.vpc.public_subnets

  security_group_ids = [
    aws_security_group.ec2_security_group.id
  ]

  private_dns_enabled = true
}


resource "aws_iam_policy" "HcdbRdsConnectSaml" {
  name = "HcdbRdsConnectSaml"
  description = "Policy to be applied via permission sets from the org account that allows specific SAML roles and users to connect to the HCDB RDS database"

  policy = jsonencode({
    "Version": "2012-10-17",
    "Id": "RdsIamAuth",
    "Statement": [
      {
        "Sid": "RdsIamAuth",
        "Action": [
          "rds-db:connect"
        ],
        "Effect": "Allow",
        "Resource": [
           "arn:aws:rds-db:us-east-2:${data.aws_caller_identity.this.account_id}:dbuser:${module.db.db_instance_resource_id}/cqread"
        ],
        "Condition": {
          "ForAnyValue:StringLike": {
            "aws:userid": "*:Jim.Weller@exampleco.com"
          }
        }
      }
    ]
  })

}