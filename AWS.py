import json
import boto3
import botocore.exceptions
import traceback
import sys

class APIKey:
    def __init__(self, api_key):
        self.api_key = api_key
        self.region = ""
        self.username = ""
        self.admin_priv = False
        self.bedrock_enabled = False
        self.logged = False
        self.useless = True
        self.useless_reasons = []

# Define AWS regions outside the class
aws_regions = [
    "us-east-2", "us-east-1", "us-west-1", "us-west-2", "af-south-1", "ap-east-1", "ap-south-2",
    "ap-southeast-3", "ap-southeast-4", "ap-south-1", "ap-northeast-3", "ap-northeast-2", "ap-southeast-1",
    "ap-southeast-2", "ap-northeast-1", "ca-central-1", "eu-central-1", "eu-west-1", "eu-west-2", "eu-south-1",
    "eu-west-3", "eu-south-2", "eu-north-1", "eu-central-2", "il-central-1", "me-south-1", "me-central-1",
    "sa-east-1"
]

def check_aws(key: APIKey):
    try:
        line = key.api_key.split(":")
        if len(line) < 2:
            print("Invalid API key format")
            return False
        
        access_key = line[0]
        secret = line[1]

        session = boto3.Session(aws_access_key_id=access_key, aws_secret_access_key=secret)
        region = get_region(session)
        print(f"Debug: Region - {region}")  # Debug print

        if region is not None:
            key.region = region
            key.useless = False
        else:
            key.useless_reasons.append('Failed Region Fetch')

        sts_client = session.client("sts")
        iam_client = session.client("iam")
        bedrock_runtime_client = session.client("bedrock-runtime")

        response = sts_client.get_caller_identity()
        print(f"Debug: Response - {response}")  # Debug print

        if response and 'Arn' in response:
            arn_parts = response['Arn'].split('/')
            key.username = arn_parts[1] if len(arn_parts) > 1 else 'default'

        policies = None
        try:
            policies = iam_client.list_attached_user_policies(UserName=key.username)['AttachedPolicies']
        except botocore.exceptions.ClientError:
            key.useless_reasons.append('Failed Policy Fetch')

        can_invoke = test_invoke_perms(bedrock_runtime_client)
        if can_invoke is not None:
            key.bedrock_enabled = True
            key.useless = False
        else:
            key.useless_reasons.append('Failed Model Invoke Check')

        if policies is not None:
            for policy in policies:
                if "AdministratorAccess" in policy["PolicyName"]:
                    key.admin_priv = True
                    key.useless = False
                    break

                policy_ver = iam_client.get_policy(PolicyArn=policy['PolicyArn'])['Policy']['DefaultVersionId']
                policy_doc = iam_client.get_policy_version(PolicyArn=policy['PolicyArn'], VersionId=policy_ver)['PolicyVersion']['Document']

                for statement in policy_doc['Statement']:
                    if statement['Effect'] == 'Allow':
                        if statement['Action'] == '*':
                            key.admin_priv = True
                            key.useless = False
                        elif 'iam:CreateUser' in statement['Action']:
                            key.useless = False
                        continue

        if not key.useless:
            check_logging(session, key)
        elif key.useless and policies is not None:
            key.useless_reasons.append('Key policies lack Admin or User Creation perms')
        return True

    except botocore.exceptions.ClientError as ce:
        traceback.print_exc()  # This will print the stack trace
        print(f"Debug: Outer ClientError - {ce}")  # Debug print
        print("Please report this on github if you see this because I missed something if this shows up.")
        return False

def get_region(session):
    for region in aws_regions:
        try:
            bedrock_client = session.client("bedrock", region_name=region)
            response = bedrock_client.list_foundation_models()
            cloudies = ['anthropic.claude-v1', 'anthropic.claude-v2']
            models = [model['modelId'] for model in response.get('modelSummaries', [])]
            if all(model_id in models for model_id in cloudies):
                return region
        except botocore.exceptions.ClientError:
            return

def test_invoke_perms(bedrock_runtime_client):
    data = {
        "prompt": "\n\nHuman:\n\nAssistant:",
        "max_tokens_to_sample": -1,
    }
    try:
        bedrock_runtime_client.invoke_model(body=json.dumps(data), modelId="anthropic.claude-instant-v1")
    except bedrock_runtime_client.exceptions.ValidationException:
        return True
    except bedrock_runtime_client.exceptions.AccessDeniedException:
        return

def check_logging(session, key: APIKey):
    try:
        bedrock_client = session.client("bedrock", region_name=key.region)
        logging_config = bedrock_client.get_model_invocation_logging_configuration()

        if 'loggingConfig' in logging_config and 'textDataDeliveryEnabled' in logging_config['loggingConfig']:
            key.logged = logging_config['loggingConfig']['textDataDeliveryEnabled']
        else:
            key.logged = False

    except botocore.exceptions.ClientError:
        return

def pretty_print_aws_keys(keys):
    print('-' * 90)
    admin_keys = [key for key in keys if key.admin_priv]
    print("Admin Keys:")
    print_keys(admin_keys)
    print('-' * 90)

    non_admin_keys = [key for key in keys if not key.admin_priv]
    print("Non-Admin Keys:")
    print_keys(non_admin_keys)
    print('-' * 90)

def print_keys(keys):
    for idx, key in enumerate(keys, 1):
        print(f"Key {idx}:")
        print(f"  API Key: {key.api_key}")
        print(f"  Username: {key.username}")
        print(f"  Region: {key.region}")
        print(f"  Bedrock Enabled: {key.bedrock_enabled}")
        print(f"  Admin Privilege: {key.admin_priv}")
        print(f"  Logged: {key.logged}")
        print(f"  Useless: {key.useless}")
        if key.useless_reasons:
            print("  Useless Reasons:")
            for reason in key.useless_reasons:
                print(f"    - {reason}")

# Example usage:
def pretty_print_aws_keys(keys):
    print('-' * 90)
    admin_keys = [key for key in keys if key.admin_priv]
    print("Admin Keys:")
    print_keys(admin_keys)
    print('-' * 90)

    non_admin_keys = [key for key in keys if not key.admin_priv]
    print("Non-Admin Keys:")
    print_keys(non_admin_keys)
    print('-' * 90)

if __name__ == "__main__":
    if len(sys.argv) < 3 or sys.argv[1] != "-file":
        print("Usage: python example.py -file <filename>")
        sys.exit(1)
    
    filename = sys.argv[2]
    
    try:
        with open(filename, "r") as file:
            api_keys = file.readlines()
        # Remove newline characters from the end of each line
        api_keys = [key.strip() for key in api_keys]
    except FileNotFoundError:
        print(f"File '{filename}' not found.")
        sys.exit(1)

    # Now api_keys contains the API keys read from the file
    keys = []
    for api_key in api_keys:
        key = APIKey(api_key)
        if check_aws(key):
            keys.append(key)

    pretty_print_aws_keys(keys)
