#!/usr/bin/env python3
import sys
import os
import json
import time

# Mock File structures representing the local filesystem and attacker workspace
VICTIM_DB_PATH = "dropbox_config.json"
ATTACKER_C2_PATH = "attacker_c2_token.json"

# Mock Cloud Files
CLOUD_STORAGE_FILES = [
  "Q3_Financials_Draft.xlsx",
  "Product_Roadmap_2027.pdf",
  "SSH_Keypair_Backup.pem"
]

def initialize_victim_environment():
    """Writes a mock sync configuration containing the OAuth token."""
    config = {
        "account_owner": "victim_user@corporate.com",
        "sync_folder_path": "/Users/victim/Dropbox",
        "oauth_refresh_token": "eyJhY2Nlc3MiOiJ1c2VyLXJlZnJlc2gtdG9rZW4teHl6LTk5MjgiLCJzaWduIjoiYmNhZDMifQ=="
    }
    with open(VICTIM_DB_PATH, "w") as f:
        json.dump(config, f, indent=2)
    print(f"[SYSTEM] Created client synchronization database: {VICTIM_DB_PATH}")

def cleanup_files():
    for path in [VICTIM_DB_PATH, ATTACKER_C2_PATH]:
        if os.path.exists(path):
            os.remove(path)

def run_lab(remediation=False):
    print("\n=======================================================")
    print("MAN-IN-THE-CLOUD (MitC) TOKEN HIJACKING LAB")
    print(f"Profile: {'REMEDIATED (TOKEN BINDING)' if remediation else 'VULNERABLE (DEFAULT)'}")
    print("=======================================================")

    print("\nStep 1: Initializing user machine environment...")
    initialize_victim_environment()
    time.sleep(0.5)

    print("\nStep 2: Attacker deploys a metadata/token harvester (Malware Agent)...")
    print("The harvester scans configuration databases of popular synchronization clients (Dropbox, OneDrive).")
    
    if not os.path.exists(VICTIM_DB_PATH):
        print("Error: Configuration file missing. Aborting.")
        return
        
    # Read the token (simulating malware exfiltration)
    print("[HARVESTER] Accessing database configuration files...")
    with open(VICTIM_DB_PATH, "r") as f:
        victim_config = json.load(f)
        
    harvested_token = victim_config.get("oauth_refresh_token")
    print(f"[HARVESTER] Successfully extracted refresh token: {harvested_token[:15]}...")
    
    # Write to attacker server file (simulating C2 exfiltration)
    with open(ATTACKER_C2_PATH, "w") as f:
        json.dump({"hijacked_token": harvested_token}, f)
    print(f"[C2 SERVER] Token stored successfully in C2 database: {ATTACKER_C2_PATH}")
    time.sleep(0.5)

    print("\nStep 3: Attacker boots a Rogue Sync Client using the harvested token...")
    print("Connecting to the Cloud Storage endpoint to request authorization...")
    
    # Load exfiltrated token
    with open(ATTACKER_C2_PATH, "r") as f:
        c2_db = json.load(f)
    token = c2_db["hijacked_token"]
    
    # Simulate authentication check against the Cloud Storage API
    print("[CLOUD API] Verifying OAuth refresh token...")
    time.sleep(0.8)
    
    if remediation:
        # Secure profile: Enforces Token Binding (verifying client-side TPM signature)
        print("[CLOUD API] Token Binding policy active. Verifying client machine hardware signature...")
        print("[CLOUD API] Checking client TPM 2.0 public key association...")
        print("\033[92m[CLOUD API] Security Alert: Token presented without corresponding TPM signature match! Access denied.\033[0m")
        print("\033[92m[REMEDIATION] Success: Attacker's Rogue Client blocked despite having a valid OAuth token.\033[0m")
    else:
        # Vulnerable profile: Accepts any client presenting the token
        print("[CLOUD API] Token is valid. Session authenticated. Sync access GRANTED.")
        print("\n\033[91m[ALERT] EXPLOIT SUCCESSFUL! Attacker's Rogue Client has bypassed authentication.\033[0m")
        print("Synchronizing Cloud directory files to Attacker's local directory:")
        for idx, filename in enumerate(CLOUD_STORAGE_FILES):
            print(f" -> Downloading [FILE {idx+1}/{len(CLOUD_STORAGE_FILES)}]: {filename} ... Done")
            time.sleep(0.3)
            
    # Cleanup files
    print("\nStep 4: Cleaning up temporary session config files...")
    cleanup_files()
    print("[SYSTEM] Temp files removed.")

if __name__ == "__main__":
    remediation = False
    if len(sys.argv) > 1 and sys.argv[1] == '--remediate':
        remediation = True
    run_lab(remediation)
