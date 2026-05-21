import requests
import random
import time 

# --- Configuration ---
API_URL = "http://127.0.0.1:8001/predict"

def generate_random_ip():
    # Randomly generate a diverse IP for GeoIP lookup
    return f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 150)}.{random.randint(1, 255)}"

def send_attack_request(ip_address, user="test@example.com"):
    
    # HTTP Headers to spoof the IP address
    headers = {
        "X-Forwarded-For": ip_address,
        "User-Agent": "Security-Tester-Script"
    }
    
    # Payload to trigger ATTACK_DETECTED status
    payload = {
        "failed_attempts_last_5min": random.randint(7, 15),
        "success_last_hour": 0,
        "distinct_usernames_per_ip": random.randint(1, 3),
        "time_between_attempts": 0.1,
        "user_email": user
    }
    
    try:
        response = requests.post(API_URL, json=payload, headers=headers)
        print(f"Sent request from {ip_address}. Status: {response.json().get('status', 'No Status')}")
    except Exception as e:
        print(f"Error sending request to FastAPI: {e}")

# --- Execution ---

print("Starting attack simulation...")
for i in range(15):
    random_ip = generate_random_ip()
    send_attack_request(random_ip, user=f"user_{i}_{random.randint(100,999)}@test.com")
    time.sleep(2) # Wait 2 seconds

print("\nSimulation finished.")