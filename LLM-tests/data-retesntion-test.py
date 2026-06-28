import boto3

client = boto3.client("bedrock", region_name="ap-southeast-2")
response = client.get_account_data_retention()
print(response)

