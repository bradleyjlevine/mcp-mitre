# MITRE ATT&CK and ATLAS MCP Server

A Model Context Protocol (MCP) server for querying MITRE ATT&CK and MITRE ATLAS (AI/ML) frameworks.

## Available Tool Functions

### ATT&CK Framework Tools

#### Summary List Functions
- `get_techniques(limit=20, offset=0)` - Get paginated list of ATT&CK techniques
- `get_tactics(limit=20, offset=0)` - Get paginated list of ATT&CK tactics
- `get_groups(limit=20, offset=0)` - Get paginated list of ATT&CK groups
- `get_software(limit=20, offset=0)` - Get paginated list of ATT&CK software
- `get_mitigations(limit=20, offset=0)` - Get paginated list of ATT&CK mitigations

#### Detailed Object Functions
- `get_technique_by_id(technique_id)` - Get full ATT&CK technique details (e.g., 'T1055')
- `get_tactic_by_id(tactic_id)` - Get full ATT&CK tactic details (e.g., 'TA0001')
- `get_mitigation_by_id(mitigation_id)` - Get full ATT&CK mitigation details (e.g., 'M1036')
- `get_group_by_alias(group_alias)` - Get full ATT&CK group details (e.g., 'APT29', 'G0019')

#### Relationship Functions
- `get_software_used_by_group(group_alias, limit=20, offset=0)` - Get software used by a specific group
- `get_techniques_used_by_group(group_alias, limit=20, offset=0)` - Get techniques used by a specific group
- `get_techniques_by_tactic(tactic_id, limit=20, offset=0)` - Get techniques belonging to a specific tactic
- `get_mitigations_for_technique(technique_id)` - Get mitigations that counter a specific technique

#### Search Functions
- `search_by_name(query, object_type="all", limit=20)` - Search ATT&CK objects by name
  - `object_type` options: 'all', 'techniques', 'tactics', 'groups', 'software', 'mitigations'

### ATLAS Framework Tools

#### Summary List Functions
- `get_atlas_techniques(limit=20, offset=0)` - Get paginated list of ATLAS techniques
- `get_atlas_tactics(limit=20, offset=0)` - Get paginated list of ATLAS tactics
- `get_atlas_mitigations(limit=20, offset=0)` - Get paginated list of ATLAS mitigations

#### Detailed Object Functions
- `get_atlas_technique_by_id(technique_id)` - Get full ATLAS technique details (e.g., 'AML.T0001')
- `get_atlas_tactic_by_id(tactic_id)` - Get full ATLAS tactic details (e.g., 'AML.TA0002', 'TA0043')
- `get_atlas_mitigation_by_id(mitigation_id)` - Get full ATLAS mitigation details (e.g., 'AML.M0001')

#### Relationship Functions
- `get_atlas_techniques_by_tactic(tactic_id, limit=20, offset=0)` - Get ATLAS techniques by tactic

#### Search Functions
- `search_atlas_by_name(query, object_type="all", limit=20)` - Search ATLAS objects by name
  - `object_type` options: 'all', 'techniques', 'tactics', 'mitigations'

#### Cross-Framework Mapping
- `get_atlas_to_attack_mapping(atlas_id)` - Get corresponding ATT&CK mappings for ATLAS items

## Usage

All functions return structured JSON data with consistent formatting for easy integration with MCP-compatible tools and applications.