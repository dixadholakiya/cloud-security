#!/usr/bin/env python3
import sys
import os

# Ensure the local path is in sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import lab modules
try:
    import soap_wrapping_lab
    import ssrf_imds_lab
    import cross_vm_cache_lab
    import man_in_the_cloud_lab
except ImportError as e:
    print(f"Error loading lab modules: {e}")
    sys.exit(1)

def clear_screen():
    # Cross-platform screen clear
    os.system('cls' if os.name == 'nt' else 'clear')

def main_menu():
    while True:
        clear_screen()
        print("\033[96m" + "="*55)
        print("     ANTIGRAVITY CLOUD SECURITY threat LAB SUITE")
        print("="*55 + "\033[0m")
        print("Select a cyber-security lab demonstration:")
        print("1) SOAP XML Wrapping (Message-Level Signature Bypass)")
        print("2) SSRF-to-IMDS (Cloud Credential Exfiltration)")
        print("3) Cross-VM Side Channel (CPU L3 Cache Sniffing)")
        print("4) Man-in-the-Cloud (OAuth Token Hijacking)")
        print("5) Exit")
        
        choice = input("\nEnter choice (1-5): ").strip()
        
        if choice == '1':
            soap_menu()
        elif choice == '2':
            ssrf_menu()
        elif choice == '3':
            cache_menu()
        elif choice == '4':
            mitc_menu()
        elif choice == '5':
            print("\nExiting lab suite. Good bye!")
            break
        else:
            input("\nInvalid choice. Press Enter to try again...")

def soap_menu():
    clear_screen()
    print("\033[93m--- SOAP XML WRAPPING LAB ---\033[0m")
    print("1) Run Vulnerable Scenario (Attacker injects unsigned duplicate Body)")
    print("2) Run Remediated Scenario (Strict XSD validation & Absolute XPath)")
    print("3) Back to Main Menu")
    
    choice = input("\nEnter choice (1-3): ").strip()
    if choice == '1':
        soap_wrapping_lab.run_lab(remediation=False)
        input("\nPress Enter to return...")
    elif choice == '2':
        soap_wrapping_lab.run_lab(remediation=True)
        input("\nPress Enter to return...")

def ssrf_menu():
    clear_screen()
    print("\033[93m--- SSRF-TO-IMDS LAB ---\033[0m")
    print("1) Run Vulnerable Scenario (Legacy IMDSv1 query)")
    print("2) Run Remediated Scenario (WAF URL Blacklisting enabled)")
    print("3) Run Remediated Scenario (IMDSv2 Session Token Enforced)")
    print("4) Back to Main Menu")
    
    choice = input("\nEnter choice (1-4): ").strip()
    if choice == '1':
        ssrf_imds_lab.run_lab(remediation_level=0)
        input("\nPress Enter to return...")
    elif choice == '2':
        ssrf_imds_lab.run_lab(remediation_level=1)
        input("\nPress Enter to return...")
    elif choice == '3':
        ssrf_imds_lab.run_lab(remediation_level=2)
        input("\nPress Enter to return...")

def cache_menu():
    clear_screen()
    print("\033[93m--- CROSS-VM CACHE SNIFFING LAB ---\033[0m")
    print("1) Run Vulnerable Scenario (Shared L3 Cache, Timing Leaks)")
    print("2) Run Remediated Scenario (Constant-Time Algorithm logic)")
    print("3) Run Remediated Scenario (Cache Partitioning / Intel CAT)")
    print("4) Back to Main Menu")
    
    choice = input("\nEnter choice (1-4): ").strip()
    if choice == '1':
        cross_vm_cache_lab.run_lab(remediation_level=0)
        input("\nPress Enter to return...")
    elif choice == '2':
        cross_vm_cache_lab.run_lab(remediation_level=1)
        input("\nPress Enter to return...")
    elif choice == '3':
        cross_vm_cache_lab.run_lab(remediation_level=2)
        input("\nPress Enter to return...")

def mitc_menu():
    clear_screen()
    print("\033[93m--- MAN-IN-THE-CLOUD LAB ---\033[0m")
    print("1) Run Vulnerable Scenario (Refresh Token stolen & rogue sync client succeeds)")
    print("2) Run Remediated Scenario (Token Binding validation denies rogue client)")
    print("3) Back to Main Menu")
    
    choice = input("\nEnter choice (1-3): ").strip()
    if choice == '1':
        man_in_the_cloud_lab.run_lab(remediation=False)
        input("\nPress Enter to return...")
    elif choice == '2':
        man_in_the_cloud_lab.run_lab(remediation=True)
        input("\nPress Enter to return...")

if __name__ == "__main__":
    try:
        main_menu()
    except KeyboardInterrupt:
        print("\n\nLab suite terminated by user.")
