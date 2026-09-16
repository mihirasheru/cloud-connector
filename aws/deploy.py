import ipaddress
import boto3
from botocore.exceptions import ClientError


# ---------------------------------------------------------
# AWS CONFIGURATION
# ---------------------------------------------------------

SECURITY_GROUP_ID = "sg-0abc60d14ac5024e9"
REGION = "ap-south-1"

# Create AWS EC2 client
ec2 = boto3.client(
    "ec2",
    region_name=REGION
)


# ---------------------------------------------------------
# SOURCE NORMALIZATION
# ---------------------------------------------------------

def normalize_source(source):
    source = source.strip()

    # Already CIDR notation
    if "/" in source:
        return source

    # Plain IP address
    try:
        ip = ipaddress.ip_address(source)
        return f"{ip}/32"

    except ValueError:
        return source


# ---------------------------------------------------------
# DEPLOYMENT VERIFICATION
# ---------------------------------------------------------

def verify_aws_policy(policy):
    """
    Check whether the expected policy exists
    in the AWS Security Group.
    """

    expected_source = normalize_source(policy.source)

    response = ec2.describe_security_groups(
        GroupIds=[SECURITY_GROUP_ID]
    )

    security_group = response["SecurityGroups"][0]

    # Check all inbound rules
    for permission in security_group.get("IpPermissions", []):

        # Check protocol
        if permission.get("IpProtocol") != "tcp":
            continue

        # Check port
        if permission.get("FromPort") != policy.port:
            continue

        if permission.get("ToPort") != policy.port:
            continue

        # Check source IP/CIDR
        for ip_range in permission.get("IpRanges", []):

            actual_source = ip_range.get("CidrIp")

            if actual_source == expected_source:

                return {
                    "verified": True,
                    "misconfiguration": False,
                    "message": "Deployed policy matches AWS configuration"
                }

    # Expected rule was not found
    return {
        "verified": False,
        "misconfiguration": True,
        "message": "Expected policy was not found in AWS Security Group"
    }


# ---------------------------------------------------------
# AWS DEPLOYMENT
# ---------------------------------------------------------

def deploy_to_aws(policy):

    # -----------------------------------------------------
    # ALLOW POLICY
    # -----------------------------------------------------

    if policy.action == "allow":

        try:

            # Add inbound rule to AWS Security Group
            ec2.authorize_security_group_ingress(
                GroupId=SECURITY_GROUP_ID,
                IpPermissions=[
                    {
                        "IpProtocol": "tcp",
                        "FromPort": policy.port,
                        "ToPort": policy.port,
                        "IpRanges": [
                            {
                                "CidrIp": normalize_source(policy.source)
                            }
                        ]
                    }
                ]
            )

            # Verify deployment
            verification = verify_aws_policy(policy)

            return {
                "status": "success",
                "provider": "aws",
                "action": "allow",
                "security_group_id": SECURITY_GROUP_ID,
                "verification": verification
            }

        except ClientError as e:

            error_code = e.response["Error"]["Code"]

            # Rule already exists
            if error_code == "InvalidPermission.Duplicate":

                verification = verify_aws_policy(policy)

                return {
                    "status": "already_exists",
                    "provider": "aws",
                    "action": "allow",
                    "security_group_id": SECURITY_GROUP_ID,
                    "verification": verification,
                    "message": "Policy already exists in AWS Security Group"
                }

            # Other AWS errors
            raise


    # -----------------------------------------------------
    # DENY POLICY
    # -----------------------------------------------------

    elif policy.action == "deny":

        try:

            # Remove inbound rule from AWS Security Group
            ec2.revoke_security_group_ingress(
                GroupId=SECURITY_GROUP_ID,
                IpPermissions=[
                    {
                        "IpProtocol": "tcp",
                        "FromPort": policy.port,
                        "ToPort": policy.port,
                        "IpRanges": [
                            {
                                "CidrIp": normalize_source(policy.source)
                            }
                        ]
                    }
                ]
            )

            return {
                "status": "success",
                "provider": "aws",
                "action": "deny",
                "security_group_id": SECURITY_GROUP_ID,
                "verification": {
                    "verified": True,
                    "misconfiguration": False,
                    "message": "Policy rule removed from AWS Security Group"
                }
            }

        except ClientError as e:

            error_code = e.response["Error"]["Code"]

            # Rule does not exist
            if error_code == "InvalidPermission.NotFound":

                return {
                    "status": "not_found",
                    "provider": "aws",
                    "action": "deny",
                    "security_group_id": SECURITY_GROUP_ID,
                    "verification": {
                        "verified": True,
                        "misconfiguration": False,
                        "message": "Policy rule was already absent from AWS Security Group"
                    }
                }

            # Other AWS errors
            raise


    # -----------------------------------------------------
    # UNSUPPORTED ACTION
    # -----------------------------------------------------

    else:

        return {
            "status": "error",
            "provider": "aws",
            "message": "Unsupported policy action"
        }