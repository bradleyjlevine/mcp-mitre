#!/usr/bin/env python3
"""
A wrapper for loading MITRE ATT&CK data with custom handling for STIX validation issues.
"""

import json
import os
from typing import Dict, List, Any, Optional, Union
import logging

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('attack_data_wrapper')

class AttackDataWrapper:
    """
    A wrapper for MITRE ATT&CK data that provides similar functionality to MitreAttackData
    but works around STIX validation issues.
    """

    def __init__(self, filepath: str):
        """
        Load ATT&CK data from a STIX file while handling validation issues.

        Args:
            filepath: Path to the STIX JSON file
        """
        self.filepath = filepath
        self.data = self._load_data()
        self.objects_by_type = self._index_by_type()
        logger.info(f"Loaded {len(self.data.get('objects', []))} objects from {filepath}")

    def _load_data(self) -> Dict[str, Any]:
        """Load and parse the STIX JSON file."""
        try:
            with open(self.filepath, 'r') as f:
                data = json.load(f)
            return data
        except Exception as e:
            logger.error(f"Failed to load {self.filepath}: {e}")
            return {"objects": []}

    def _index_by_type(self) -> Dict[str, List[Dict[str, Any]]]:
        """Index objects by their type for faster lookups."""
        index = {}
        for obj in self.data.get('objects', []):
            obj_type = obj.get('type')
            if obj_type:
                if obj_type not in index:
                    index[obj_type] = []
                index[obj_type].append(obj)
        return index

    def get_all_by_type(self, obj_type: str) -> List[Dict[str, Any]]:
        """Get all objects of a specific type."""
        return self.objects_by_type.get(obj_type, [])

    def get_techniques(self) -> List[Dict[str, Any]]:
        """Get all ATT&CK techniques."""
        return self.get_all_by_type('attack-pattern')

    def get_tactics(self) -> List[Dict[str, Any]]:
        """Get all ATT&CK tactics."""
        return self.get_all_by_type('x-mitre-tactic')

    def get_groups(self) -> List[Dict[str, Any]]:
        """Get all ATT&CK groups."""
        return self.get_all_by_type('intrusion-set')

    def get_software(self) -> List[Dict[str, Any]]:
        """Get all ATT&CK software."""
        malware = self.get_all_by_type('malware')
        tools = self.get_all_by_type('tool')
        return malware + tools

    def get_mitigations(self) -> List[Dict[str, Any]]:
        """Get all ATT&CK mitigations."""
        return self.get_all_by_type('course-of-action')

    def get_groups_by_alias(self, alias: str) -> List[Dict[str, Any]]:
        """
        Get groups that match a specific alias.

        Args:
            alias: Group alias to search for

        Returns:
            List of matching group objects
        """
        matching_groups = []
        for group in self.get_groups():
            # Check if the group has this alias
            if alias == group.get('name'):
                matching_groups.append(group)
                continue

            # Check aliases list
            aliases = group.get('aliases', [])
            if alias in aliases:
                matching_groups.append(group)

        return matching_groups

    def get_techniques_by_tactic(self, tactic_shortname: str, domain: str = "enterprise-attack") -> List[Dict[str, Any]]:
        """
        Get techniques associated with a specific tactic.

        Args:
            tactic_shortname: The tactic shortname (e.g., "initial-access")
            domain: The ATT&CK domain (default: "enterprise-attack")

        Returns:
            List of technique objects
        """
        matching_techniques = []
        for technique in self.get_techniques():
            # Check if technique belongs to this tactic
            for phase in technique.get('kill_chain_phases', []):
                if (phase.get('kill_chain_name') == 'mitre-attack' and
                    phase.get('phase_name') == tactic_shortname):
                    # Check if technique is in the requested domain
                    domains = technique.get('x_mitre_domains', [])
                    if domain in domains:
                        matching_techniques.append(technique)
                        break

        return matching_techniques

    def get_relationships(self, relationship_type: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Get relationship objects, optionally filtered by relationship type.

        Args:
            relationship_type: Optional relationship type to filter by

        Returns:
            List of relationship objects
        """
        relationships = self.get_all_by_type('relationship')

        if relationship_type:
            return [r for r in relationships if r.get('relationship_type') == relationship_type]

        return relationships

    def get_software_used_by_group(self, group_stix_id: str) -> List[Dict[str, Any]]:
        """
        Get software used by a specific group.

        Args:
            group_stix_id: STIX ID of the group

        Returns:
            List of software objects
        """
        relationships = self.get_relationships('uses')

        software_ids = []
        for rel in relationships:
            if rel.get('source_ref') == group_stix_id:
                target_ref = rel.get('target_ref', '')
                if target_ref.startswith('malware--') or target_ref.startswith('tool--'):
                    software_ids.append(target_ref)

        # Get the actual software objects
        software_objects = []
        all_software = self.get_software()

        for sw in all_software:
            if sw.get('id') in software_ids:
                software_objects.append({'object': sw})

        return software_objects

    def get_techniques_used_by_group(self, group_stix_id: str) -> List[Dict[str, Any]]:
        """
        Get techniques used by a specific group.

        Args:
            group_stix_id: STIX ID of the group

        Returns:
            List of technique objects
        """
        relationships = self.get_relationships('uses')

        technique_ids = []
        for rel in relationships:
            if rel.get('source_ref') == group_stix_id:
                target_ref = rel.get('target_ref', '')
                if target_ref.startswith('attack-pattern--'):
                    technique_ids.append(target_ref)

        # Get the actual technique objects
        technique_objects = []
        all_techniques = self.get_techniques()

        for tech in all_techniques:
            if tech.get('id') in technique_ids:
                technique_objects.append({'object': tech})

        return technique_objects

    def get_all_mitigations_mitigating_all_techniques(self) -> Dict[str, List[Dict[str, Any]]]:
        """
        Get all mitigations that mitigate techniques.

        Returns:
            Dict mapping technique IDs to lists of mitigation objects
        """
        result = {}
        relationships = self.get_relationships('mitigates')

        for rel in relationships:
            source_ref = rel.get('source_ref', '')
            target_ref = rel.get('target_ref', '')

            # Skip if not mitigation->technique relationship
            if not source_ref.startswith('course-of-action--') or not target_ref.startswith('attack-pattern--'):
                continue

            if target_ref not in result:
                result[target_ref] = []

            # Find the mitigation object
            for mitigation in self.get_mitigations():
                if mitigation.get('id') == source_ref:
                    result[target_ref].append({'object': mitigation})
                    break

        return result

# Direct function for loading MITRE ATT&CK data
def load_attack_data(filepath: str) -> AttackDataWrapper:
    """
    Load MITRE ATT&CK data from a STIX file.

    Args:
        filepath: Path to the STIX JSON file

    Returns:
        AttackDataWrapper instance
    """
    return AttackDataWrapper(filepath)