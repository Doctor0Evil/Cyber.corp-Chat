# utils/auth.py  
def create_access_token(data: dict, expires_delta: int = None):  
    to_encode = data.copy()  
    expire = datetime.datetime.utcnow() + datetime.timedelta(minutes=expires_delta or ACCESS_TOKEN_EXPIRE_MINUTES)  
    to_encode.update({"exp": expire})  
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)  
\\
# providers.tf  
provider "aws" {  
  region     = "us-east-1"  
  access_key = var.vsc_access_key  
  secret_key = var.vsc_secret_key  
}  

provider "kubernetes" {  
  host                   = module.eks.cluster_endpoint  
  cluster_ca_certificate = base64decode(module.eks.cluster_certificate_authority_data)  
  token                  = data.aws_eks_cluster_auth.cluster.token  
}  

provider "helm" {  
  kubernetes {  
    host                   = module.eks.cluster_endpoint  
    cluster_ca_certificate = base64decode(module.eks.cluster_certificate_authority_data)  
    token                  = data.aws_eks_cluster_auth.cluster.token  
  }  
}  
\\
# modules/eks/main.tf  
resource "aws_eks_cluster" "cluster" {  
  name     = "vsc-eks"  
  version  = "1.29"  
  vpc_config {  
    vpc_id           = module.vpc.vpc_id  
    subnet_ids       = module.vpc.private_subnets  
    endpoint_public_access = false  
    endpoint_private_access = true  
  }  
  tags = {  
    Name = "vsc-eks"  
    Environment = "Cyber.corp-Chat"  
  }  
}  

resource "aws_iam_role" "eks_node_role" {  
  name = "eks-node-role"  
  assume_role_policy = jsonencode({  
    Version = "2012-10-17"  
    Statement = [{  
      Effect = "Allow"  
      Principal = { Service = "ec2.amazonaws.com" }  
      Action = "sts:AssumeRole"  
    }]  
  })  
}  

resource "aws_iam_role_policy_attachment" "eks_node_policy" {  
  role       = aws_iam_role.eks_node_role.name  
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSServicePolicy"  
}  
\\
# modules/k8s/main.tf  
resource "kubernetes_deployment" "app" {  
  metadata {  
    name = "vsc-app"  
    labels = {  
      app = "vsc"  
    }  
  }  
  spec {  
    replicas = 3  
    selector {  
      match_labels = {  
        app = "vsc"  
      }  
    }  
    template {  
      metadata {  
        labels = {  
          app = "vsc"  
        }  
      }  
      spec {  
        container {  
          image = "vsc/app:latest"  
          name  = "vsc-app"  
          port {  
            container_port = 80  
          }  
        }  
      }  
    }  
  }  
}  
\\
# root/main.tf  
module "eks" {  
  source = "./modules/eks"  
}  

module "k8s" {  
  source = "./modules/k8s"  
}  

# VPC Module  
module "vpc" {  
  source  = "terraform-aws-modules/vpc/aws"  
  version = "~> 5.0"  
  name    = "vsc-vpc"  
  cidr    = "10.0.0.0/16"  
  azs     = ["us-east-1a", "us-east-1b", "us-east-1c"]  
  private_subnets = ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]  
  public_subnets  = ["10.0.101.0/24", "10.0.102.0/24", "10.0.103.0/24"]  
  enable_nat_gateway = true  
  enable_vpn_gateway = true  
  tags = {  
    Name = "vsc-vpc"  
    Environment = "Cyber.corp-Chat"  
  }  
}  

# KMS Encryption Key  
resource "aws_kms_key" "vsc_encryption" {  
  description             = "KMS key for VSC storage encryption"  
  enable_key_rotation     = true  
  tags = {  
    Name = "vsc-kms"  
  }  
}  

# MinIO Storage  
resource "aws_s3_bucket" "minio" {  
  bucket = "vsc-minio-cybercorp"  
  tags = {  
    Name = "vsc-minio"  
  }  
  server_side_encryption_configuration {  
    rule {  
      apply_server_side_encryption_by_default {  
        sse_algorithm = "aws:kms"  
        kms_master_key_id = aws_kms_key.vsc_encryption.arn  
      }  
    }  
  }  
}  

# PostgreSQL Instance  
resource "aws_db_instance" "postgres" {  
  identifier         = "vsc-postgres"  
  instance_class     = "db.t3.medium"  
  engine             = "postgres"  
  engine_version     = "15"  
  username           = var.postgres_username  
  password           = var.postgres_password  
  db_name            = "vsc_db"  
  allocated_storage  = 20  
  storage_type       = "gp2"  
  skip_final_snapshot = true  
  tags = {  
    Name = "vsc-postgres"  
  }  
}  
\\
# variables.tf  
variable "vsc_access_key" { type = string, sensitive = true }  
variable "vsc_secret_key" { type = string, sensitive = true }  
variable "postgres_username" { type = string, sensitive = true }  
variable "postgres_password" { type = string, sensitive = true }  

# outputs.tf  
output "eks_cluster_endpoint" {  
  value = module.eks.cluster_endpoint  
}  
output "minio_endpoint" {  
  value = "http://${helm_release.minio.name}-minio.storage.svc.cluster.local"  
}  
output "postgres_endpoint" {  
  value = aws_db_instance.postgres.address  
}  
