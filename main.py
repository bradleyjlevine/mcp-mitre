from fastmcp import FastMCP
from mitreattack.stix20 import MitreAttackData
import yaml

def _get_attr_or_key(obj, key, default=None):
    """Get attribute from object or key from dict, with fallback to default."""
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)

def _stix_obj_to_dict(obj):
    """Convert STIX object to dictionary representation."""
    if obj is None:
        return {}
    if isinstance(obj, dict):
        return obj
    return {k: getattr(obj, k, None) for k in dir(obj) if not k.startswith("_") and not callable(getattr(obj, k, None))}

def _extract_mitre_id(obj):
    """Extract MITRE ATT&CK ID from external references."""
    d = obj
    for ref in d.get("external_references", []):
        if ref.get("external_id") and ref.get("source_name") and ref.get("source_name") == "mitre-attack":
            return ref["external_id"]
    return None

def _summary(obj):
    """Create summary object with id, mitre_id, name, and description."""
    d = obj
    return {
        "id": d.get("id") or _get_attr_or_key(obj, "id"),
        "mitre_id": _extract_mitre_id(obj),
        "name": d.get("name") or _get_attr_or_key(obj, "name"),
        "description": d.get("description") or _get_attr_or_key(obj, "description") or ""
    }

def _atlas_summary(obj):
    """Create summary object for ATLAS data with ATT&CK reference mapping."""
    mitre_id = None
    attck_ref = obj.get("ATT&CK-reference", {})
    if isinstance(attck_ref, dict):
        mitre_id = attck_ref.get("id")
    return {
        "id": obj.get("id"),
        "mitre_id": mitre_id,
        "name": obj.get("name"),
        "description": obj.get("description", None)
    }

def _atlas_tactic_by_id(atlas_tactics, query_id):
    """Find ATLAS tactic by ID or ATT&CK reference ID (case-insensitive)."""
    query_id = query_id.upper()
    for t in atlas_tactics:
        if t.get("id", "").upper() == query_id:
            return t
        attck_ref = t.get("ATT&CK-reference", {})
        if isinstance(attck_ref, dict) and attck_ref.get("id", "").upper() == query_id:
            return t
    return {}

def _atlas_find_by_id(collection, query_id):
    """Find object in ATLAS collection by ID (case-insensitive)."""
    query_id = query_id.upper()
    for obj in collection:
        if obj.get("id", "").upper() == query_id:
            return obj
    return {}

# --- Load ATT&CK and ATLAS data
attack_data = MitreAttackData("enterprise-attack.json")
with open("ATLAS.yaml", "r") as f:
    atlas_data = yaml.safe_load(f)
atlas_matrix = atlas_data["matrices"][0]
atlas_tactics = atlas_matrix["tactics"]
atlas_techniques = atlas_matrix["techniques"]
atlas_mitigations = atlas_matrix["mitigations"]

mcp = FastMCP(
    name="ATTACK + ATLAS MCP Server",
    instructions="Query MITRE ATT&CK and MITRE ATLAS (AI/ML) frameworks via Model Context Protocol."
)

# ---------- ATT&CK summary endpoints (testable helpers and MCP wrappers) ----------

def _get_attack_data_paginated(data_getter_func, limit=20, offset=0):
    """Generic helper for paginated ATT&CK data with summaries.
    
    Args:
        data_getter_func: Function to retrieve data from attack_data
        limit: Maximum number of items to return
        offset: Number of items to skip
        
    Returns:
        Dict with 'items' (list of summaries) and 'total' (total count)
    """
    all_items = list(data_getter_func())
    paged = all_items[offset:offset+limit]
    summaries = [_summary(item) for item in paged]
    return {"items": summaries, "total": len(all_items)}

def _get_techniques(limit=20, offset=0):
    """Get paginated list of ATT&CK technique summaries."""
    return _get_attack_data_paginated(attack_data.get_techniques, limit, offset)

@mcp.tool(
    name="get_techniques",
    description="Return a paginated summary list of ATT&CK techniques.",
    output_schema={"type": "object", "properties": {"items": {"type": "array", "items": {"type": "object"}}, "total": {"type": "integer"}}}
)
def get_techniques(limit: int = 20, offset: int = 0):
    """MCP tool wrapper for getting ATT&CK techniques."""
    return _get_techniques(limit, offset)

def _get_tactics(limit=20, offset=0):
    """Get paginated list of ATT&CK tactic summaries."""
    return _get_attack_data_paginated(attack_data.get_tactics, limit, offset)

@mcp.tool(
    name="get_tactics",
    description="Return a paginated summary list of ATT&CK tactics.",
    output_schema={"type": "object", "properties": {"items": {"type": "array", "items": {"type": "object"}}, "total": {"type": "integer"}}}
)
def get_tactics(limit: int = 20, offset: int = 0):
    """MCP tool wrapper for getting ATT&CK tactics."""
    return _get_tactics(limit, offset)

def _get_groups(limit=20, offset=0):
    """Get paginated list of ATT&CK group summaries."""
    return _get_attack_data_paginated(attack_data.get_groups, limit, offset)

@mcp.tool(
    name="get_groups",
    description="Return a paginated summary list of ATT&CK groups.",
    output_schema={"type": "object", "properties": {"items": {"type": "array", "items": {"type": "object"}}, "total": {"type": "integer"}}}
)
def get_groups(limit: int = 20, offset: int = 0):
    """MCP tool wrapper for getting ATT&CK groups."""
    return _get_groups(limit, offset)

def _get_software(limit=20, offset=0):
    """Get paginated list of ATT&CK software summaries."""
    return _get_attack_data_paginated(attack_data.get_software, limit, offset)

@mcp.tool(
    name="get_software",
    description="Return a paginated summary list of ATT&CK software.",
    output_schema={"type": "object", "properties": {"items": {"type": "array", "items": {"type": "object"}}, "total": {"type": "integer"}}}
)
def get_software(limit: int = 20, offset: int = 0):
    """MCP tool wrapper for getting ATT&CK software."""
    return _get_software(limit, offset)

def _get_mitigations(limit=20, offset=0):
    """Get paginated list of ATT&CK mitigation summaries."""
    return _get_attack_data_paginated(attack_data.get_mitigations, limit, offset)

@mcp.tool(
    name="get_mitigations",
    description="Return a paginated summary list of ATT&CK mitigations.",
    output_schema={"type": "object", "properties": {"items": {"type": "array", "items": {"type": "object"}}, "total": {"type": "integer"}}}
)
def get_mitigations(limit: int = 20, offset: int = 0):
    """MCP tool wrapper for getting ATT&CK mitigations."""
    return _get_mitigations(limit, offset)

# ---------- ATT&CK by-ID endpoints (testable helpers and MCP wrappers) ----------

def _get_technique_by_id(technique_id):
    """Get detailed ATT&CK technique by MITRE ID (e.g., 'T1055').
    
    Args:
        technique_id: MITRE technique ID (case-insensitive)
        
    Returns:
        Dict with technique details or empty dict if not found
    """
    tech_id = technique_id.upper()
    for t in attack_data.get_techniques():
        d = t
        for ref in d.get("external_references", []):
            if ref.get("external_id") and ref.get("source_name") and ref.get("source_name") == "mitre-attack" and ref.get("external_id") == tech_id:
                return {
                    "name": d.get("name", None),
                    "description": d.get("description", None),
                    "id": d.get("id", None),
                    "type": d.get("type", None),
                    "mitre_link": ref.get("url", None),
                    "x_mitre_data_sources": list(d.get("x_mitre_data_sources", [])),
                    "x_mitre_detection": d.get("x_mitre_detection", None),
                    "x_mitre_platforms": list(d.get("x_mitre_platforms", [])),
                    "x_mitre_domains": list(d.get("x_mitre_domains", [])),
                    "kill_chain_phases": [p.get("phase_name", None) for p in d.get("kill_chain_phases", []) if p.get("phase_name")]
                }
    return {}

@mcp.tool(
    name="get_technique_by_id",
    description="Return full ATT&CK technique object for MITRE technique ID (e.g., 'T1055').",
    output_schema={"type": "object"}
)
def get_technique_by_id(technique_id: str):
    """MCP tool wrapper for getting ATT&CK technique by ID."""
    return _get_technique_by_id(technique_id)

def _get_tactic_by_id(tactic_id):
    """Get detailed ATT&CK tactic by MITRE ID (e.g., 'TA0001').
    
    Args:
        tactic_id: MITRE tactic ID (case-insensitive)
        
    Returns:
        Dict with tactic details or empty dict if not found
    """
    tactic_id = tactic_id.upper()
    for t in attack_data.get_tactics():
        d = t
        for ref in d.get("external_references", []):
            if ref.get("external_id") and ref.get("source_name") and ref.get("source_name") == "mitre-attack" and ref.get("external_id") == tactic_id:
                return {
                    "name": d.get("name", None),
                    "description": d.get("description", None),
                    "id": d.get("id", None),
                    "type": d.get("type", None),
                    "mitre_link": ref.get("url", None),
                    "x_mitre_shortname": d.get("x_mitre_shortname", None)
                }
    return {}

@mcp.tool(
    name="get_tactic_by_id",
    description="Return full ATT&CK tactic object for MITRE tactic ID (e.g., 'TA0001').",
    output_schema={"type": "object"}
)
def get_tactic_by_id(tactic_id: str):
    """MCP tool wrapper for getting ATT&CK tactic by ID."""
    return _get_tactic_by_id(tactic_id)

def _get_mitigation_by_id(mitigation_id):
    """Get detailed ATT&CK mitigation by MITRE ID (e.g., 'M1036').
    
    Args:
        mitigation_id: MITRE mitigation ID (case-insensitive)
        
    Returns:
        Dict with mitigation details or empty dict if not found
    """
    mitigation_id = mitigation_id.upper()
    for m in attack_data.get_mitigations():
        d = m
        for ref in d.get("external_references", []):
            if ref.get("external_id") and ref.get("source_name") and ref.get("source_name") == "mitre-attack" and ref.get("external_id") == mitigation_id:
                return {
                    "name": d.get("name", None),
                    "description": d.get("description", None),
                    "id": d.get("id", None),
                    "type": d.get("type", None),
                    "mitre_link": ref.get("url", None),
                    "x_mitre_shortname": d.get("x_mitre_shortname", None),
                    "x_mitre_domains": list(d.get("x_mitre_domains", []))
                }
    return {}

@mcp.tool(
    name="get_mitigation_by_id",
    description="Return full ATT&CK mitigation object for MITRE mitigation ID (e.g., 'M1036').",
    output_schema={"type": "object"}
)
def get_mitigation_by_id(mitigation_id: str):
    """MCP tool wrapper for getting ATT&CK mitigation by ID."""
    return _get_mitigation_by_id(mitigation_id)


def _get_group_by_alias(group_alias):
    """Get detailed ATT&CK group by alias (e.g., 'APT29', 'G0019').
    
    Args:
        group_alias: Group alias (case-sensitive)
        
    Returns:
        Dict with group details or empty dict if not found
    """
    for g in attack_data.get_groups_by_alias(group_alias):
        d = g
        for ref in d.get("external_references", []):
            if ref.get("external_id") and ref.get("source_name") and ref.get("source_name") == "mitre-attack":
                return {
                    "name": d.get("name", None),
                    "description": d.get("description", None),
                    "id": d.get("id", None),
                    "type": d.get("type", None),
                    "mitre_link": ref.get("url", None),
                    "external_references": [{"source_name": r.get("source_name", None), "description": r.get("description", None), "url": r.get("url", None) } for r in d.get("external_references", []) if r.get("source_name") != "mitre-attack"],
                    "x_mitre_contributors": list(d.get("x_mitre_contributors", [])),
                    "aliases": list(d.get("aliases", [])),
                    "x_mitre_domains": list(d.get("x_mitre_domains", []))
                }
    return {}

@mcp.tool(
    name="get_group_by_alias",
    description="Return full ATT&CK group object for MITRE mitigation ID (e.g., 'G0019').  You must use one of the aliases the group is known by, for example G0019 is know by 'APT29' or 'UNC2452' or 'UNC3524' or 'Midnight Blizzard'.  This is case-sensitive.",
    output_schema={"type": "object"}
)
def get_group_by_alias(group_alias: str):
    """MCP tool wrapper for getting ATT&CK group by alias."""
    return _get_group_by_alias(group_alias)

def _get_software_used_by_group(group_alias):
    """Get software used by a specific ATT&CK group.
    
    Args:
        group_alias: Group alias like 'APT29', 'G0016', etc.
        
    Returns:
        Dict with 'items' (list of software summaries) and 'total' count
    """
    # Get the group first to find its STIX ID
    group_stix_id = None
    for group in attack_data.get_groups_by_alias(group_alias):
        group_dict = group
        group_stix_id = group_dict.get("id")
        break
    
    if not group_stix_id:
        return {"items": [], "total": 0}
    
    # Use the built-in method to get software used by this group
    software_objects = attack_data.get_software_used_by_group(group_stix_id)
    software_list = []
    
    for s in software_objects:
        # The software objects are wrapped in a dict with 'object' key
        software_obj = s.get('object') if isinstance(s, dict) and 'object' in s else s
        software_list.append(_summary(software_obj))
    
    return {"items": software_list, "total": len(software_list)}

@mcp.tool(
    name="get_software_used_by_group",
    description="Return software used by a specific ATT&CK group. Use group alias like 'APT29', 'G0016', etc.",
    output_schema={"type": "object", "properties": {"items": {"type": "array", "items": {"type": "object"}}, "total": {"type": "integer"}}}
)
def get_software_used_by_group(group_alias: str):
    """MCP tool wrapper for getting software used by group."""
    return _get_software_used_by_group(group_alias)

def _get_techniques_used_by_group(group_alias):
    """Get techniques used by a specific ATT&CK group.
    
    Args:
        group_alias: Group alias like 'APT29', 'G0016', etc.
        
    Returns:
        Dict with 'items' (list of technique summaries) and 'total' count
    """
    # Get the group first to find its STIX ID
    group_stix_id = None
    for group in attack_data.get_groups_by_alias(group_alias):
        group_dict = group
        group_stix_id = group_dict.get("id")
        break
    
    if not group_stix_id:
        return {"items": [], "total": 0}
    
    # Use the built-in method to get techniques used by this group
    technique_objects = attack_data.get_techniques_used_by_group(group_stix_id)
    technique_list = []
    
    for t in technique_objects:
        # The technique objects are wrapped in a dict with 'object' key
        technique_obj = t.get('object') if isinstance(t, dict) and 'object' in t else t
        technique_list.append(_summary(technique_obj))
    
    return {"items": technique_list, "total": len(technique_list)}

@mcp.tool(
    name="get_techniques_used_by_group",
    description="Return techniques used by a specific ATT&CK group. Use group alias like 'APT29', 'G0016', etc.",
    output_schema={"type": "object", "properties": {"items": {"type": "array", "items": {"type": "object"}}, "total": {"type": "integer"}}}
)
def get_techniques_used_by_group(group_alias: str):
    """MCP tool wrapper for getting techniques used by group."""
    return _get_techniques_used_by_group(group_alias)

def _get_techniques_by_tactic(tactic_id, limit=20, offset=0):
    """Get techniques that belong to a specific tactic.
    
    Args:
        tactic_id: MITRE tactic ID (e.g., 'TA0001') or shortname (e.g., 'initial-access')
        limit: Maximum number of items to return
        offset: Number of items to skip
        
    Returns:
        Dict with 'items' (list of technique summaries) and 'total' count
    """
    # Convert tactic ID to shortname if needed
    tactic_shortname = tactic_id
    if tactic_id.upper().startswith('TA'):
        # Look up the tactic to get its shortname
        tactic_info = _get_tactic_by_id(tactic_id)
        if tactic_info and tactic_info.get('x_mitre_shortname'):
            tactic_shortname = tactic_info['x_mitre_shortname']
        else:
            return {"items": [], "total": 0}
    
    # Use the built-in method to get techniques for this tactic (enterprise domain)
    technique_objects = attack_data.get_techniques_by_tactic(tactic_shortname, "enterprise-attack")
    all_techniques = list(technique_objects)
    
    # Apply pagination
    paged = all_techniques[offset:offset+limit]
    technique_list = [_summary(t) for t in paged]
    
    return {"items": technique_list, "total": len(all_techniques)}

@mcp.tool(
    name="get_techniques_by_tactic",
    description="Return techniques that belong to a specific ATT&CK tactic. Use tactic ID like 'TA0001', 'TA0002', etc.",
    output_schema={"type": "object", "properties": {"items": {"type": "array", "items": {"type": "object"}}, "total": {"type": "integer"}}}
)
def get_techniques_by_tactic(tactic_id: str, limit: int = 20, offset: int = 0):
    """MCP tool wrapper for getting techniques by tactic."""
    return _get_techniques_by_tactic(tactic_id, limit, offset)

def _get_mitigations_for_technique(technique_id):
    """Get mitigations that counter a specific technique.
    
    Args:
        technique_id: MITRE technique ID (e.g., 'T1055') - case-insensitive
        
    Returns:
        Dict with 'items' (list of mitigation summaries) and 'total' count
    """
    # First find the technique STIX ID from the technique ID
    technique_stix_id = None
    technique_id_upper = technique_id.upper()
    
    for technique in attack_data.get_techniques():
        tech_dict = technique
        for ref in tech_dict.get("external_references", []):
            if (ref.get("external_id") and ref.get("source_name") == "mitre-attack" and 
                ref.get("external_id") == technique_id_upper):
                technique_stix_id = tech_dict.get("id")
                break
        if technique_stix_id:
            break
    
    if not technique_stix_id:
        return {"items": [], "total": 0}
    
    # Get all mitigation relationships and find ones for this technique STIX ID
    all_relationships = attack_data.get_all_mitigations_mitigating_all_techniques()
    mitigation_list = []
    
    if technique_stix_id in all_relationships:
        mitigations = all_relationships[technique_stix_id]
        for m in mitigations:
            # The mitigation objects are wrapped in a dict with 'object' key
            mitigation_obj = m.get('object') if isinstance(m, dict) and 'object' in m else m
            mitigation_summary = _summary(mitigation_obj)
            mitigation_list.append(mitigation_summary)
    
    return {"items": mitigation_list, "total": len(mitigation_list)}

@mcp.tool(
    name="get_mitigations_for_technique",
    description="Return mitigations that counter a specific ATT&CK technique. Use technique ID like 'T1055', 'T1003', etc.",
    output_schema={"type": "object", "properties": {"items": {"type": "array", "items": {"type": "object"}}, "total": {"type": "integer"}}}
)
def get_mitigations_for_technique(technique_id: str):
    """MCP tool wrapper for getting mitigations for technique."""
    return _get_mitigations_for_technique(technique_id)

def _search_by_name(query, object_type="all", limit=20):
    """Search across ATT&CK objects by name (case-insensitive).
    
    Args:
        query: Search term to match against names
        object_type: Type to search - 'all', 'techniques', 'tactics', 'groups', 'software', 'mitigations'
        limit: Maximum number of results to return
        
    Returns:
        Dict with 'items' (list of matching summaries) and 'total' count
    """
    results = []
    query_lower = query.lower()
    
    # Define search functions for each object type
    search_targets = {
        'techniques': attack_data.get_techniques,
        'tactics': attack_data.get_tactics, 
        'groups': attack_data.get_groups,
        'software': attack_data.get_software,
        'mitigations': attack_data.get_mitigations
    }
    
    # Determine which object types to search
    if object_type == "all":
        types_to_search = search_targets.keys()
    elif object_type in search_targets:
        types_to_search = [object_type]
    else:
        return {"items": [], "total": 0, "error": f"Unknown object_type: {object_type}"}
    
    # Search each object type
    for obj_type in types_to_search:
        for obj in search_targets[obj_type]():
            obj_dict = obj
            name = obj_dict.get('name', '')
            if name and query_lower in name.lower():
                summary = _summary(obj_dict)
                summary['object_type'] = obj_type  # Add type for clarity
                results.append(summary)
                
                # Stop if we've hit the limit
                if len(results) >= limit:
                    break
        
        if len(results) >= limit:
            break
    
    return {"items": results[:limit], "total": len(results)}

@mcp.tool(
    name="search_by_name",
    description="Search ATT&CK objects by name. Use object_type to filter: 'all', 'techniques', 'tactics', 'groups', 'software', 'mitigations'.",
    output_schema={"type": "object", "properties": {"items": {"type": "array", "items": {"type": "object"}}, "total": {"type": "integer"}}}
)
def search_by_name(query: str, object_type: str = "all", limit: int = 20):
    """MCP tool wrapper for searching by name."""
    return _search_by_name(query, object_type, limit)

# ---------- ATLAS summary endpoints (testable helpers and MCP wrappers) ----------

def _get_atlas_techniques(limit=20, offset=0):
    """Get paginated list of ATLAS technique summaries."""
    paged = atlas_techniques[offset:offset+limit]
    summaries = [_atlas_summary(t) for t in paged]
    return {"items": summaries, "total": len(atlas_techniques)}

@mcp.tool(
    name="get_atlas_techniques",
    description="Return a paginated summary list of ATLAS techniques.",
    output_schema={"type": "object", "properties": {"items": {"type": "array", "items": {"type": "object"}}, "total": {"type": "integer"}}}
)
def get_atlas_techniques(limit: int = 20, offset: int = 0):
    """MCP tool wrapper for getting ATLAS techniques."""
    return _get_atlas_techniques(limit, offset)

def _get_atlas_tactics(limit=20, offset=0):
    """Get paginated list of ATLAS tactic summaries."""
    paged = atlas_tactics[offset:offset+limit]
    summaries = [_atlas_summary(t) for t in paged]
    return {"items": summaries, "total": len(atlas_tactics)}

@mcp.tool(
    name="get_atlas_tactics",
    description="Return a paginated summary list of ATLAS tactics.",
    output_schema={"type": "object", "properties": {"items": {"type": "array", "items": {"type": "object"}}, "total": {"type": "integer"}}}
)
def get_atlas_tactics(limit: int = 20, offset: int = 0):
    """MCP tool wrapper for getting ATLAS tactics."""
    return _get_atlas_tactics(limit, offset)

def _get_atlas_mitigations(limit=20, offset=0):
    """Get paginated list of ATLAS mitigation summaries."""
    paged = atlas_mitigations[offset:offset+limit]
    summaries = [_atlas_summary(m) for m in paged]
    return {"items": summaries, "total": len(atlas_mitigations)}

@mcp.tool(
    name="get_atlas_mitigations",
    description="Return a paginated summary list of ATLAS mitigations.",
    output_schema={"type": "object", "properties": {"items": {"type": "array", "items": {"type": "object"}}, "total": {"type": "integer"}}}
)
def get_atlas_mitigations(limit: int = 20, offset: int = 0):
    """MCP tool wrapper for getting ATLAS mitigations."""
    return _get_atlas_mitigations(limit, offset)

# ---------- ATLAS by-ID endpoints (testable helpers and MCP wrappers) ----------

def _get_atlas_technique_by_id(technique_id):
    """Get detailed ATLAS technique by ID (e.g., 'AML.T0001')."""
    return _atlas_find_by_id(atlas_techniques, technique_id)

@mcp.tool(
    name="get_atlas_technique_by_id",
    description="Return the full ATLAS technique object for ATLAS ID (e.g., 'AML.T0001').",
    output_schema={"type": "object"}
)
def get_atlas_technique_by_id(technique_id: str):
    """MCP tool wrapper for getting ATLAS technique by ID."""
    return _get_atlas_technique_by_id(technique_id)

def _get_atlas_tactic_by_id(tactic_id):
    """Get detailed ATLAS tactic by ID or ATT&CK reference ID."""
    return _atlas_tactic_by_id(atlas_tactics, tactic_id)

@mcp.tool(
    name="get_atlas_tactic_by_id",
    description="Return the full ATLAS tactic object for ATLAS or ATT&CK ID (e.g., 'AML.TA0002', 'TA0043').",
    output_schema={"type": "object"}
)
def get_atlas_tactic_by_id(tactic_id: str):
    """MCP tool wrapper for getting ATLAS tactic by ID."""
    return _get_atlas_tactic_by_id(tactic_id)

def _get_atlas_mitigation_by_id(mitigation_id):
    """Get detailed ATLAS mitigation by ID (e.g., 'AML.M0001')."""
    return _atlas_find_by_id(atlas_mitigations, mitigation_id)

@mcp.tool(
    name="get_atlas_mitigation_by_id",
    description="Return the full ATLAS mitigation object for ATLAS ID (e.g., 'AML.M0001').",
    output_schema={"type": "object"}
)
def get_atlas_mitigation_by_id(mitigation_id: str):
    """MCP tool wrapper for getting ATLAS mitigation by ID."""
    return _get_atlas_mitigation_by_id(mitigation_id)

# ---------- Additional ATLAS functions ----------

def _search_atlas_by_name(query, object_type="all", limit=20):
    """Search across ATLAS objects by name (case-insensitive).
    
    Args:
        query: Search term to match against names
        object_type: Type to search - 'all', 'techniques', 'tactics', 'mitigations'
        limit: Maximum number of results to return
        
    Returns:
        Dict with 'items' (list of matching summaries) and 'total' count
    """
    results = []
    query_lower = query.lower()
    
    # Define search collections for each object type
    search_targets = {
        'techniques': atlas_techniques,
        'tactics': atlas_tactics,
        'mitigations': atlas_mitigations
    }
    
    # Determine which object types to search
    if object_type == "all":
        types_to_search = search_targets.keys()
    elif object_type in search_targets:
        types_to_search = [object_type]
    else:
        return {"items": [], "total": 0, "error": f"Unknown object_type: {object_type}"}
    
    # Search each object type
    for obj_type in types_to_search:
        for obj in search_targets[obj_type]:
            name = obj.get('name', '')
            if name and query_lower in name.lower():
                summary = _atlas_summary(obj)
                summary['object_type'] = obj_type  # Add type for clarity
                results.append(summary)
                
                # Stop if we've hit the limit
                if len(results) >= limit:
                    break
        
        if len(results) >= limit:
            break
    
    return {"items": results[:limit], "total": len(results)}

@mcp.tool(
    name="search_atlas_by_name",
    description="Search ATLAS objects by name. Use object_type to filter: 'all', 'techniques', 'tactics', 'mitigations'.",
    output_schema={"type": "object", "properties": {"items": {"type": "array", "items": {"type": "object"}}, "total": {"type": "integer"}}}
)
def search_atlas_by_name(query: str, object_type: str = "all", limit: int = 20):
    """MCP tool wrapper for searching ATLAS by name."""
    return _search_atlas_by_name(query, object_type, limit)

def _get_atlas_techniques_by_tactic(tactic_id, limit=20, offset=0):
    """Get ATLAS techniques that belong to a specific tactic.
    
    Args:
        tactic_id: ATLAS tactic ID (e.g., 'AML.TA0002') or ATT&CK ID (e.g., 'TA0043')
        limit: Maximum number of items to return
        offset: Number of items to skip
        
    Returns:
        Dict with 'items' (list of technique summaries) and 'total' count
    """
    # Find the tactic first to validate it exists
    tactic_info = _atlas_tactic_by_id(atlas_tactics, tactic_id)
    if not tactic_info:
        return {"items": [], "total": 0}
    
    # Get the actual ATLAS tactic ID to match against technique tactic fields
    atlas_tactic_id = tactic_info.get('id', '')
    if not atlas_tactic_id:
        return {"items": [], "total": 0}
    
    # Find techniques that belong to this tactic
    matching_techniques = []
    for technique in atlas_techniques:
        # Check if this technique belongs to the tactic
        technique_tactics = technique.get('tactics', [])
        if atlas_tactic_id in technique_tactics:
            matching_techniques.append(technique)
    
    # Apply pagination
    paged = matching_techniques[offset:offset+limit]
    technique_list = [_atlas_summary(t) for t in paged]
    
    return {"items": technique_list, "total": len(matching_techniques)}

@mcp.tool(
    name="get_atlas_techniques_by_tactic",
    description="Return ATLAS techniques that belong to a specific tactic. Use ATLAS tactic ID like 'AML.TA0002' or ATT&CK ID like 'TA0043'.",
    output_schema={"type": "object", "properties": {"items": {"type": "array", "items": {"type": "object"}}, "total": {"type": "integer"}}}
)
def get_atlas_techniques_by_tactic(tactic_id: str, limit: int = 20, offset: int = 0):
    """MCP tool wrapper for getting ATLAS techniques by tactic."""
    return _get_atlas_techniques_by_tactic(tactic_id, limit, offset)

def _get_atlas_to_attack_mapping(atlas_id):
    """Get corresponding ATT&CK techniques/tactics for an ATLAS item.
    
    Args:
        atlas_id: ATLAS ID (e.g., 'AML.T0001', 'AML.TA0002', 'AML.M0001')
        
    Returns:
        Dict with ATLAS item details and ATT&CK mappings
    """
    atlas_id_upper = atlas_id.upper()
    atlas_item = None
    item_type = None
    
    # Find the ATLAS item across all collections (check longer prefixes first)
    if atlas_id_upper.startswith('AML.TA'):
        atlas_item = _atlas_tactic_by_id(atlas_tactics, atlas_id)
        item_type = "tactic"
    elif atlas_id_upper.startswith('AML.T'):
        atlas_item = _atlas_find_by_id(atlas_techniques, atlas_id)
        item_type = "technique"
    elif atlas_id_upper.startswith('AML.M'):
        atlas_item = _atlas_find_by_id(atlas_mitigations, atlas_id)
        item_type = "mitigation"
    else:
        return {"error": f"Unknown ATLAS ID format: {atlas_id}"}
    
    if not atlas_item:
        return {"error": f"ATLAS item not found: {atlas_id}"}
    
    # Extract ATT&CK reference
    attack_mapping = None
    attck_ref = atlas_item.get("ATT&CK-reference", {})
    if isinstance(attck_ref, dict) and attck_ref.get("id"):
        attack_id = attck_ref.get("id")
        
        # Get the corresponding ATT&CK item details
        if item_type == "technique":
            attack_mapping = _get_technique_by_id(attack_id)
        elif item_type == "tactic":
            attack_mapping = _get_tactic_by_id(attack_id)
        elif item_type == "mitigation":
            attack_mapping = _get_mitigation_by_id(attack_id)
    
    return {
        "atlas_item": _atlas_summary(atlas_item),
        "atlas_full": atlas_item,
        "attack_mapping": attack_mapping,
        "item_type": item_type
    }

@mcp.tool(
    name="get_atlas_to_attack_mapping",
    description="Get corresponding ATT&CK mappings for an ATLAS item. Use ATLAS ID like 'AML.T0001', 'AML.TA0002', 'AML.M0001'.",
    output_schema={"type": "object"}
)
def get_atlas_to_attack_mapping(atlas_id: str):
    """MCP tool wrapper for getting ATLAS to ATT&CK mappings."""
    return _get_atlas_to_attack_mapping(atlas_id)

if __name__ == "__main__":
    mcp.run()
