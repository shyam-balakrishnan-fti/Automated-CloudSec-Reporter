import requests
import os
import json


BEDROCK_API_KEY = os.environ["BEDROCK_API_KEY"]

response = requests.put(
    "https://bedrock-mantle.ap-southeast-2.api.aws/v1/models/anthropic.claude-opus-4.8",
    headers={
        "x-api-key": BEDROCK_API_KEY,
        "Content-Type": "application/json"
    },
    json={"mode": "none"}
)
print(json.dumps(response.json(), indent=2))
