#!/usr/bin/env python3
import sys
import xml.etree.ElementTree as ET

# Define namespaces
NS = {
    'soapenv': 'http://schemas.xmlsoap.org/soap/envelope/',
    'wsse': 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd',
    'wsu': 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd',
    'ds': 'http://www.w3.org/2000/09/xmldsig#'
}

# Register namespaces for printing
for prefix, uri in NS.items():
    ET.register_namespace(prefix, uri)

# Legitimate SOAP Request (Vulnerable format)
VULNERABLE_SOAP_PAYLOAD = """<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
                  xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
  <soapenv:Header>
    <wsse:Security xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
      <!-- Legitimate WS-Security Signature Block referencing Body wsu:Id="Original" -->
      <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:SignedInfo>
          <ds:Reference URI="#Original"/>
        </ds:SignedInfo>
        <ds:SignatureValue>Base64ValidSignatureHashValueHere==</ds:SignatureValue>
      </ds:Signature>
    </wsse:Security>
  </soapenv:Header>
  <!-- legitimate, signed body block -->
  <soapenv:Body wsu:Id="Original">
    <operation>GetAccountDetails</operation>
    <accountID>10029</accountID>
  </soapenv:Body>
</soapenv:Envelope>"""

# Attacker wrapped SOAP Request (Injecting second body block)
ATTACK_SOAP_PAYLOAD = """<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
                  xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
  <soapenv:Header>
    <wsse:Security xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
      <!-- Attacker intercepts request and copies signature unchanged -->
      <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:SignedInfo>
          <ds:Reference URI="#Original"/>
        </ds:SignedInfo>
        <ds:SignatureValue>Base64ValidSignatureHashValueHere==</ds:SignatureValue>
      </ds:Signature>
    </wsse:Security>
  </soapenv:Header>
  <!-- Attacker wraps the original signed element in a nested wrapper tag -->
  <wrapper:FakeWrapper xmlns:wrapper="http://attacker.net/wrapper">
    <soapenv:Body wsu:Id="Original">
      <operation>GetAccountDetails</operation>
      <accountID>10029</accountID>
    </soapenv:Body>
  </wrapper:FakeWrapper>
  <!-- Attacker injects second malicious, unsigned body block -->
  <soapenv:Body wsu:Id="Malicious">
    <operation>TransferAllFunds</operation>
    <targetAccount>99823-Attacker-Node</targetAccount>
    <amount>ALL</amount>
  </soapenv:Body>
</soapenv:Envelope>"""

def mock_verify_signature(xml_tree, verbose=True):
    """
    Simulates signature verification. The engine parses the document, 
    locates the Signature Reference URI, matches it with the element ID,
    and validates the hash.
    """
    if verbose:
        print("[VERIFIER] XML Document received. Scanning WS-Security Headers...")
    
    # Locate Signature Reference
    root = xml_tree.getroot()
    ref_el = root.find('.//ds:Reference', NS)
    
    if ref_el is None:
        print("[VERIFIER] Error: No Security Signature reference found. Request rejected.")
        return False
        
    target_uri = ref_el.attrib.get('URI', '').replace('#', '')
    if verbose:
        print(f"[VERIFIER] Found Signature Reference pointing to URI: #{target_uri}")
        
    # Search document for the element matching the target ID
    # Naive verifier searches using a flexible XPath/ID matching lookup
    signed_block = None
    for el in root.iter():
        for attr, val in el.attrib.items():
            if attr.endswith('Id') and val == target_uri:
                signed_block = el
                break
        if signed_block is not None:
            break
            
    if signed_block is None:
        print(f"[VERIFIER] Error: Target element wsu:Id='{target_uri}' not found in DOM.")
        return False
        
    if verbose:
        print(f"[VERIFIER] Signature matches element <{signed_block.tag}> wsu:Id='{target_uri}' successfully.")
        print("[VERIFIER] Hash matches signature payload. Signature: [VALID]")
    
    # Returns the target ID that was validated
    return target_uri

def vulnerable_business_logic(xml_tree):
    """
    Vulnerable parsing logic. Instead of executing the verified node block,
    the application queries the DOM naively using a generic tag query.
    It takes the first or last <Body> element found in the DOM hierarchy.
    """
    print("\n[APP LOGIC] Starting request execution...")
    root = xml_tree.getroot()
    
    # Naive query: extracts ALL soapenv:Body elements
    body_elements = root.findall('.//soapenv:Body', NS)
    
    if not body_elements:
        print("[APP LOGIC] Error: No SOAP body element found in message.")
        return
        
    print(f"[APP LOGIC] Loose parser found {len(body_elements)} <Body> tag(s) inside DOM.")
    
    # Vulnerable implementation bias: selects the last element or parses loosely
    # In XML Wrapping, the first signed body is wrapped inside another tag, 
    # so a direct tag query retrieves the secondary un-wrapped malicious body block first or last
    executed_body = body_elements[-1]
    
    body_id = "unknown"
    for attr, val in executed_body.attrib.items():
        if attr.endswith('Id'):
            body_id = val
            
    print(f"[APP LOGIC] Selecting node with wsu:Id='{body_id}' for database operation.")
    print(f"[APP LOGIC] XML Element details: Tag={executed_body.tag}, ID={body_id}")
    
    # Extract inner commands
    operation = executed_body.find('operation')
    op_text = operation.text if operation is not None else "None"
    
    print(f"[APP LOGIC] Executed database operation: [{op_text.upper()}]")
    if op_text == 'TransferAllFunds':
        target = executed_body.find('targetAccount').text
        print(f"\033[91m[ALERT] EXPLOIT SUCCESSFUL! Funds exfiltrated to account: {target}\033[0m")
    else:
        print("[STATUS] Success: Legitimate details returned.")

def secure_business_logic(xml_tree, verified_id):
    """
    Remediated parsing logic. Uses absolute XPath referencing, binding
    the execution strictly to the verified XML block.
    """
    print("\n[SECURE APP LOGIC] Starting secure request execution...")
    root = xml_tree.getroot()
    
    # Absolute XPath binding target block
    # /soapenv:Envelope/soapenv:Body[@wsu:Id='Original']
    # If the verifier validated 'Original', we ONLY execute that exact ID.
    print(f"[SECURE APP LOGIC] Enforcing binding. Querying strictly for wsu:Id='{verified_id}'...")
    
    executed_body = None
    for el in root.findall('.//soapenv:Body', NS):
        for attr, val in el.attrib.items():
            if attr.endswith('Id') and val == verified_id:
                executed_body = el
                break
                
    if executed_body is None:
         print("[SECURE APP LOGIC] Security Error: Absolute XPath query failed. Elements did not match validated signature.")
         return
         
    # Check duplicate body tags schema violation
    all_bodies = root.findall('.//soapenv:Body', NS)
    if len(all_bodies) > 1:
        print("\033[92m[REMEDIATION] Shield Check: Duplicate <Body> nodes detected! Potential XML Wrapping Attack. Request aborted.\033[0m")
        return
        
    operation = executed_body.find('operation')
    op_text = operation.text if operation is not None else "None"
    print(f"[SECURE APP LOGIC] Executed operation: [{op_text}]")
    print("\033[92m[STATUS] Secure execution completed. Attacker payload ignored.\033[0m")

def run_lab(remediation=False):
    print("\n=======================================================")
    print("SOAP XML WRAPPING ATTACK LAB DEMONSTRATION")
    print(f"Profile: {'REMEDIATED (SECURE)' if remediation else 'VULNERABLE (DEFAULT)'}")
    print("=======================================================")
    
    # Parse the attacker-modified SOAP document
    print("\nStep 1: Attacker intercepting legitimate communication...")
    print("Attacker wraps original body element in wrapper block and inserts duplicate body containing malicious commands.")
    
    try:
        xml_tree = ET.ElementTree(ET.fromstring(ATTACK_SOAP_PAYLOAD))
    except Exception as e:
        print(f"Error parsing XML payload: {e}")
        return
        
    print("\nStep 2: Message reaches Server. Signature Verification Engine starts...")
    verified_id = mock_verify_signature(xml_tree)
    
    if not verified_id:
        print("Signature verification failed. Transaction cancelled.")
        return
        
    print("\nStep 3: Signature passed. Forwarding payload block to application processing...")
    
    if remediation:
        secure_business_logic(xml_tree, verified_id)
    else:
        vulnerable_business_logic(xml_tree)

if __name__ == "__main__":
    remediation = False
    if len(sys.argv) > 1 and sys.argv[1] == '--remediate':
        remediation = True
    run_lab(remediation)
