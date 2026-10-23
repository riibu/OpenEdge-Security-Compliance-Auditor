import json
import requests

# Point to localhost on your Windows host; VirtualBox port forwarding 
# will automatically tunnel this traffic to your Kali VM's port 11434.
OLLAMA_URL = "http://localhost:11434/api/generate"

# Specify your model
payload = {
    "model": "llama3.1",
    "prompt": "Hello Orion! Confirming system connection. Reply with a brief status check.",
    "stream": False,
}

print(f"[*] Sending request to Ollama via Port Forwarding at {OLLAMA_URL}...")

try:
  response = requests.post(OLLAMA_URL, json=payload)

  if response.status_code == 200:
    result = response.json()
    print("\n[+] Response received successfully from Orion:\n")
    print(result.get("response", "No response field found."))
  else:
    print(
        f"\n[-] Error: Received status code {response.status_code} -"
        f" {response.text}"
    )

except requests.exceptions.ConnectionError:
  print(
      "\n[-] Connection Error: Could not connect. Double-check your VirtualBox"
      " Port Forwarding rules (Host Port 11434 -> Guest Port 11434) and make sure"
      " Ollama is running inside Kali."
  )
except Exception as e:
  print(f"\n[-] An unexpected error occurred: {e}")