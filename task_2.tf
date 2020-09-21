 // AWS prvider details
provider "aws" {
  region = "ap-south-1"
  profile = "mycloud"
}

//Create Security Group
resource "aws_security_group" "http_protocol" {
  name        = "allow_http_port"
  description = "Allow http traffic"
  vpc_id      = "vpc-fccb2b97"
  ingress {
    description = "HTTP from VPC"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    description = "ssh from VPC"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
 ingress {
    from_port = 2049
    to_port   = 2049
    protocol  = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
 egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    from_port = 2049
    to_port   = 2049
    protocol  = "tcp"
     cidr_blocks = ["0.0.0.0/0"]
  }
  tags = {
    Name = "allow_http_port"
  }
}
//Create Key Pair and Save
resource "tls_private_key" "key_ssh" {
  depends_on = [aws_security_group.http_protocol]
   algorithm  = "RSA"
  rsa_bits   = 4096
}
resource "aws_key_pair" "key3" {
  key_name   = "key3"
  public_key = tls_private_key.key_ssh.public_key_openssh
}
output "key_ssh" {
  value = tls_private_key.key_ssh.private_key_pem
}
resource "local_file" "save_key" {
    content     = tls_private_key.key_ssh.private_key_pem
    filename = "key3.pem"
}
//create Ec2 instance
resource "aws_instance" "apache" {
  depends_on = [aws_key_pair.key3,tls_private_key.key_ssh,local_file.save_key]
  ami           = "ami-0447a12f28fddb066"
  instance_type = "t2.micro"
  key_name = "key3"
  security_groups = [ "allow_http_port" ]
  tags = {
    Name = "apache_webserver"
  }
}
//create efs volume
resource "aws_efs_file_system" "h_efs" {
  depends_on = [aws_instance.apache]
  tags = {
    creation_token = "my-efs"
    Name = "Myefs"
  }
}
resource "aws_efs_mount_target" "alpha" {
  depends_on = [aws_efs_file_system.h_efs]
  file_system_id = aws_efs_file_system.h_efs.id
  subnet_id      = "subnet-98737af0"
  security_groups = [ aws_security_group.http_protocol.id ]
}
//saving the public ip
resource "null_resource" "nulllocal2"  {
        provisioner "local-exec" {
            command = "echo  ${aws_instance.apache.public_ip} > publicip.txt"
        }
}
//connect to ec-2 and install dependencies
resource "null_resource" "nullremote3"  {
depends_on = [aws_efs_mount_target.alpha]
  connection {
    type     = "ssh"
    user     = "ec2-user"
    private_key = tls_private_key.key_ssh.private_key_pem
    host     = aws_instance.apache.public_ip
  }
provisioner "remote-exec" {
    inline = [
	  "sudo yum install httpd -y",
      "sudo yum install git -y",
      "sudo systemctl restart httpd",
      "sudo systemctl enable httpd",
      "sudo yum install amazon-efs-utils -y",
      "sudo rm -rf /var/www/html/*",
      "sudo git clone https://github.com/hitebrata/hybrid_cc_task_2.git /var/www/html/"
     ]
  }
}
resource "null_resource" "nulllocal1"  {
depends_on = [null_resource.nullremote3,]

        provisioner "local-exec" {
            command = "start chrome  ${aws_instance.apache.public_ip}"
  }
}
//Create S3 bucket and deploy the images from github repo into the s3 bucket and change the permission to public readable.
resource "null_resource" "null2"  {
  provisioner "local-exec" {
      command = "git clone https://github.com/hitebrata/hybrid_cc_task_2.git ./gitcode"
    }
}

resource "aws_s3_bucket" "hitabrata0000" {
  depends_on = [null_resource.nullremote3]
  bucket = "hitabrata0000"
  acl    = "public-read"
  versioning {
  enabled = true
}
  tags = {
    Name        = "hitabrata0000"
    Environment = "operation"
  }
}
resource "aws_s3_bucket_object" "hb_bucket" {
  depends_on = [aws_s3_bucket.hitabrata0000]
  key = "DevOps_lifecycle.jpg"
  bucket = aws_s3_bucket.hitabrata0000.id
  source = "./gitcode/DevOps_lifecycle.jpg"
  acl = "public-read"
}
//create origin access identity
resource "aws_cloudfront_origin_access_identity" "cloudfront_origin_access_identity" {
  comment = "Origina access identity"
}
//Create a Cloudfront using s3 bucket which contains images and use the Cloudfront URL to update in code in /var/www/htmL
resource "aws_cloudfront_distribution" "cloudfront1" {
   depends_on = [aws_s3_bucket_object.hb_bucket]
    origin {
        domain_name = "mycode.s3.amazonaws.com"
        origin_id = aws_s3_bucket.hitabrata0000.id
        custom_origin_config {
            http_port = 80
            https_port = 80
            origin_protocol_policy = "match-viewer"
            origin_ssl_protocols = ["TLSv1", "TLSv1.1", "TLSv1.2"]
        }
    }
    enabled = true
    default_cache_behavior {
        allowed_methods = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]
        cached_methods = ["GET", "HEAD"]
        target_origin_id = aws_s3_bucket.hitabrata0000.id
        forwarded_values {
            query_string = false
            cookies {
               forward = "none"
            }
        }
        viewer_protocol_policy = "allow-all"
        min_ttl = 0
        default_ttl = 3600
        max_ttl = 86400
    }
    restrictions {
        geo_restriction {
            restriction_type = "none"
        }
    }
    viewer_certificate {
        cloudfront_default_certificate = true
    }
}
