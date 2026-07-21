import os
import re
import subprocess

# Define paths
md_path = "/Users/user/antigravity-cloud/unit_2_cloud_security.md"
docx_path = "/Users/user/antigravity-cloud/unit_2_cloud_security.docx"
diagrams_dir = "/Users/user/antigravity-cloud/diagrams"

# Expected diagram filenames mapped to order in markdown file
DIAGRAM_FILENAMES = [
    "unit2_shared_responsibility.png",
    "unit2_capital_one_ssrf.png",
    "unit2_scoutsuite_lifecycle.png",
    "unit2_privesc_rollback.png",
    "unit2_session_hijack_mfa.png",
    "unit2_impossible_travel_logic.png",
    "unit2_session_cookie_capture.png",
    "unit2_syn_flood_simulation.png",
    "unit2_ddos_reflection.png",
    "unit2_traffic_classifier_flow.png",
    "unit2_secure_web_server.png",
    "unit2_risk_register_flow.png",
]

# Ensure output directory exists
os.makedirs(diagrams_dir, exist_ok=True)

# Read markdown content
with open(md_path, "r", encoding="utf-8") as f:
    content = f.read()

# Find all ```mermaid ... ``` blocks
pattern = re.compile(r"```mermaid\n(.*?)\n```", re.DOTALL)
matches = pattern.findall(content)

print(f"Found {len(matches)} Mermaid diagrams in {md_path}")

if len(matches) != 12:
    print(f"Warning: Expected 12 diagrams, but found {len(matches)}.")

# Render each diagram using mmdc
for i, block in enumerate(matches):
    if i < len(DIAGRAM_FILENAMES):
        filename = DIAGRAM_FILENAMES[i]
    else:
        filename = f"unit2_diagram_{i+1}.png"
    
    mmd_temp_path = os.path.join(diagrams_dir, f"temp_{i}.mmd")
    png_path = os.path.join(diagrams_dir, filename)
    
    # Write temp mermaid file
    with open(mmd_temp_path, "w", encoding="utf-8") as temp_f:
        temp_f.write(block)
    
    print(f"[{i+1}/{len(matches)}] Rendering {filename}...")
    
    # Run mmdc command with white background
    cmd = [
        "/opt/homebrew/bin/mmdc",
        "-i", mmd_temp_path,
        "-o", png_path,
        "-b", "white"
    ]
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        print(f"Error rendering diagram {i+1}:")
        print(res.stderr)
    
    # Clean up temp file
    if os.path.exists(mmd_temp_path):
        os.remove(mmd_temp_path)

# Update markdown content to replace mermaid code blocks with image references
updated_content = content
for i, block in enumerate(matches):
    if i < len(DIAGRAM_FILENAMES):
        filename = DIAGRAM_FILENAMES[i]
    else:
        filename = f"unit2_diagram_{i+1}.png"
    
    block_string = f"```mermaid\n{block}\n```"
    image_markdown = f"![Diagram {i+1}](./diagrams/{filename})"
    updated_content = updated_content.replace(block_string, image_markdown)

# Write to a temp markdown file for pandoc conversion
temp_md_compiled = "/Users/user/antigravity-cloud/unit_2_cloud_security_compiled.md"
with open(temp_md_compiled, "w", encoding="utf-8") as temp_f:
    temp_f.write(updated_content)

print("Compiling markdown to DOCX using Pandoc...")
pandoc_cmd = [
    "/opt/homebrew/bin/pandoc",
    temp_md_compiled,
    "-o", docx_path,
    "--toc"
]

res = subprocess.run(pandoc_cmd, capture_output=True, text=True)
if res.returncode != 0:
    print("Error compiling with Pandoc:")
    print(res.stderr)
else:
    print(f"Successfully compiled {docx_path}!")

# Update original markdown file with the version referencing images
with open(md_path, "w", encoding="utf-8") as f:
    f.write(updated_content)
print(f"Successfully updated original markdown file: {md_path}")

# Clean up temp file
if os.path.exists(temp_md_compiled):
    os.remove(temp_md_compiled)
