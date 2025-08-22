import main

# Save as test_mcp_tools.py and run: python test_mcp_tools.py
# Assumes your main code is in the same interpreter context.

def print_header(name):
    print(f"\n{'-'*30}\n{name}\n{'-'*30}")

# Call paginated summary endpoints for ATT&CK
print_header("ATT&CK Techniques - Summary")
result = main._get_techniques(limit=3, offset=0)
print(result)

print_header("ATT&CK Tactics - Summary")
result = main._get_tactics(limit=3, offset=0)
print(result)

print_header("ATT&CK Groups - Summary")
result = main._get_groups(limit=3, offset=0)
print(result)

print_header("ATT&CK Software - Summary")
result = main._get_software(limit=3, offset=0)
print(result)

print_header("ATT&CK Mitigations - Summary")
result = main._get_mitigations(limit=3, offset=0)
print(result)

# Test "get by ID" with real MITRE IDs from your data
print_header("ATT&CK Technique by ID (T1055)")
result = main._get_technique_by_id("T1055")
print(result if result else "Not found")

print_header("ATT&CK Tactic by ID (TA0001)")
result = main._get_tactic_by_id("TA0001")
print(result if result else "Not found")

print_header("ATT&CK Mitigation by ID (M1036)")
result = main._get_mitigation_by_id("M1036")
print(result if result else "Not found")

print_header("ATT&CK Group by Alias (APT29)")
result = main._get_group_by_alias("APT29")
print(result if result else "Not found")

# Call paginated summary endpoints for ATLAS
print_header("ATLAS Techniques - Summary")
result = main._get_atlas_techniques(limit=3, offset=0)
print(result)

print_header("ATLAS Tactics - Summary")
result = main._get_atlas_tactics(limit=3, offset=0)
print(result)

print_header("ATLAS Mitigations - Summary")
result = main._get_atlas_mitigations(limit=3, offset=0)
print(result)

# Test "get by ID" for ATLAS (use real IDs from your ATLAS.yaml)
atlas_technique_id = "AML.T0000"
atlas_tactic_id = "AML.TA0002"
atlas_mitigation_id = "AML.M0000"

print_header(f"ATLAS Technique by ID ({atlas_technique_id})")
result = main._get_atlas_technique_by_id(atlas_technique_id)
print(result if result else "Not found")

print_header(f"ATLAS Tactic by ID ({atlas_tactic_id})")
result = main._get_atlas_tactic_by_id(atlas_tactic_id)
print(result if result else "Not found")

print_header(f"ATLAS Mitigation by ID ({atlas_mitigation_id})")
result = main._get_atlas_mitigation_by_id(atlas_mitigation_id)
print(result if result else "Not found")
