import requests
import os

BEDROCK_API_KEY = os.environ["BEDROCK_API_KEY"]

response = requests.get(
    "https://bedrock-mantle.us-east-1.api.aws/v1/models/anthropic.claude-opus-4-8",
    headers={
        "x-api-key": BEDROCK_API_KEY,
        "Content-Type": "application/json"
    }
)

import json
print(json.dumps(response.json(), indent=2))
