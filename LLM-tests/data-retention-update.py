import boto3

client = boto3.client("bedrock", region_name="ap-southeast-2")
response = client.put_account_data_retention(mode="none")
print(response)

