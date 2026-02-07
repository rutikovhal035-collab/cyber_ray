"""
YARA Rule Generator
Automatically generates YARA rules from analysis results
"""

import re
import hashlib
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime

# Optional YARA import
try:
    import yara
    HAS_YARA = True
except ImportError:
    HAS_YARA = False
    print("Warning: yara-python not installed. YARA validation disabled.")


class YARAGenerator:
    """Generates YARA rules from malware analysis results"""
    
    # String patterns to exclude (too common/noisy)
    EXCLUDE_PATTERNS = [
        r'^[a-zA-Z]$',  # Single letters
        r'^\d+$',  # Just numbers
        r'^[\s\W]+$',  # Just whitespace/punctuation
        r'^(the|and|for|this|that|with)$',  # Common words
    ]
    
    # Maximum strings per rule
    MAX_STRINGS = 20
    
    def generate_rule(
        self,
        task_id: str,
        static_analysis: Optional[Dict[str, Any]],
        dynamic_analysis: Optional[Dict[str, Any]],
        rule_name: Optional[str] = None,
        include_strings: bool = True,
        include_imports: bool = True,
        include_hashes: bool = True
    ) -> str:
        """
        Generate a YARA rule from analysis results
        
        Args:
            task_id: Analysis task ID
            static_analysis: Static analysis results
            dynamic_analysis: Dynamic analysis results
            rule_name: Optional custom rule name
            include_strings: Include suspicious strings
            include_imports: Include suspicious imports
            include_hashes: Include file hashes in metadata
            
        Returns:
            YARA rule as string
        """
        # Generate rule name
        if not rule_name:
            rule_name = self._sanitize_rule_name(f"malware_{task_id[:8]}")
        else:
            rule_name = self._sanitize_rule_name(rule_name)
        
        # Build metadata section
        meta = self._build_metadata(task_id, static_analysis, include_hashes)
        
        # Build strings section
        strings = []
        
        if include_strings and static_analysis:
            strings.extend(self._extract_yara_strings(
                static_analysis.get("suspicious_strings", [])
            ))
        
        if include_imports and static_analysis:
            pe_info = static_analysis.get("pe_info", {})
            if pe_info:
                strings.extend(self._extract_import_strings(
                    pe_info.get("suspicious_imports", [])
                ))
        
        # Add dynamic analysis indicators
        if dynamic_analysis:
            strings.extend(self._extract_behavior_strings(dynamic_analysis))
        
        # Deduplicate and limit strings
        strings = self._deduplicate_strings(strings)[:self.MAX_STRINGS]
        
        # Build condition
        condition = self._build_condition(static_analysis, len(strings))
        
        # Assemble rule
        rule = self._assemble_rule(rule_name, meta, strings, condition)
        
        return rule
    
    def _sanitize_rule_name(self, name: str) -> str:
        """Sanitize rule name to be YARA-compliant"""
        # Replace invalid characters
        name = re.sub(r'[^a-zA-Z0-9_]', '_', name)
        # Ensure starts with letter or underscore
        if name and name[0].isdigit():
            name = '_' + name
        return name
    
    def _build_metadata(
        self, 
        task_id: str, 
        static_analysis: Optional[Dict[str, Any]],
        include_hashes: bool
    ) -> List[Tuple[str, str]]:
        """Build YARA metadata section"""
        meta = [
            ("author", "Malware Analysis Sandbox"),
            ("date", datetime.now().strftime("%Y-%m-%d")),
            ("description", f"Auto-generated rule from analysis {task_id}"),
            ("task_id", task_id)
        ]
        
        if include_hashes and static_analysis:
            hashes = static_analysis.get("hashes", {})
            if hashes.get("md5"):
                meta.append(("md5", hashes["md5"]))
            if hashes.get("sha256"):
                meta.append(("sha256", hashes["sha256"]))
            if hashes.get("ssdeep"):
                meta.append(("ssdeep", hashes["ssdeep"]))
        
        if static_analysis:
            file_type = static_analysis.get("file_type", "")
            if file_type:
                meta.append(("filetype", file_type[:50]))
        
        return meta
    
    def _extract_yara_strings(self, suspicious_strings: List[str]) -> List[Dict[str, Any]]:
        """Convert suspicious strings to YARA string definitions"""
        yara_strings = []
        
        for i, s in enumerate(suspicious_strings):
            # Skip if matches exclusion pattern
            if self._should_exclude_string(s):
                continue
            
            # Escape special characters
            escaped = self._escape_yara_string(s)
            
            if escaped:
                string_def = {
                    "name": f"$str_{i}",
                    "value": escaped,
                    "type": "text",
                    "modifiers": ["ascii", "wide", "nocase"]
                }
                yara_strings.append(string_def)
        
        return yara_strings
    
    def _extract_import_strings(self, suspicious_imports: List[str]) -> List[Dict[str, Any]]:
        """Convert suspicious imports to YARA strings"""
        yara_strings = []
        
        for i, imp in enumerate(suspicious_imports):
            # Format: "dll:function"
            if ":" in imp:
                func = imp.split(":")[1]
            else:
                func = imp
            
            string_def = {
                "name": f"$imp_{i}",
                "value": self._escape_yara_string(func),
                "type": "text",
                "modifiers": ["ascii"]
            }
            yara_strings.append(string_def)
        
        return yara_strings
    
    def _extract_behavior_strings(self, dynamic_analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract strings from dynamic analysis behavior"""
        yara_strings = []
        idx = 0
        
        # Extract from network activity
        network = dynamic_analysis.get("network_activity", [])
        for conn in network[:5]:
            if conn.get("domain"):
                yara_strings.append({
                    "name": f"$net_{idx}",
                    "value": self._escape_yara_string(conn["domain"]),
                    "type": "text",
                    "modifiers": ["ascii", "wide"]
                })
                idx += 1
        
        # Extract from file operations
        file_ops = dynamic_analysis.get("file_operations", [])
        for op in file_ops[:5]:
            path = op.get("path", "")
            # Extract filename from path
            if "\\" in path:
                filename = path.split("\\")[-1]
                if len(filename) > 4:
                    yara_strings.append({
                        "name": f"$file_{idx}",
                        "value": self._escape_yara_string(filename),
                        "type": "text",
                        "modifiers": ["ascii", "wide", "nocase"]
                    })
                    idx += 1
        
        return yara_strings
    
    def _should_exclude_string(self, s: str) -> bool:
        """Check if string should be excluded from YARA rule"""
        # Too short
        if len(s) < 4:
            return True
        
        # Too long
        if len(s) > 200:
            return True
        
        # Matches exclusion pattern
        for pattern in self.EXCLUDE_PATTERNS:
            if re.match(pattern, s, re.IGNORECASE):
                return True
        
        return False
    
    def _escape_yara_string(self, s: str) -> str:
        """Escape string for YARA rule"""
        # Escape backslashes and quotes
        s = s.replace("\\", "\\\\")
        s = s.replace('"', '\\"')
        # Remove null bytes
        s = s.replace("\x00", "")
        # Remove/escape control characters
        s = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', s)
        return s
    
    def _deduplicate_strings(self, strings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Remove duplicate strings"""
        seen_values = set()
        unique = []
        
        for s in strings:
            value = s.get("value", "").lower()
            if value and value not in seen_values:
                seen_values.add(value)
                unique.append(s)
        
        return unique
    
    def _build_condition(self, static_analysis: Optional[Dict[str, Any]], num_strings: int) -> str:
        """Build YARA condition section"""
        conditions = []
        
        # PE file check
        if static_analysis and static_analysis.get("pe_info", {}).get("is_pe"):
            conditions.append("uint16(0) == 0x5A4D")  # MZ header
        
        # String matching
        if num_strings > 0:
            if num_strings <= 3:
                conditions.append("all of them")
            elif num_strings <= 6:
                conditions.append(f"{num_strings - 1} of them")
            else:
                # Require about 50% of strings
                required = max(3, num_strings // 2)
                conditions.append(f"{required} of them")
        
        if not conditions:
            conditions.append("true")
        
        return " and ".join(conditions)
    
    def _assemble_rule(
        self, 
        name: str, 
        meta: List[Tuple[str, str]], 
        strings: List[Dict[str, Any]], 
        condition: str
    ) -> str:
        """Assemble the final YARA rule"""
        lines = [f"rule {name} {{"]
        
        # Metadata
        lines.append("    meta:")
        for key, value in meta:
            lines.append(f'        {key} = "{value}"')
        
        # Strings
        if strings:
            lines.append("")
            lines.append("    strings:")
            for s in strings:
                modifiers = " ".join(s.get("modifiers", []))
                lines.append(f'        {s["name"]} = "{s["value"]}" {modifiers}'.rstrip())
        
        # Condition
        lines.append("")
        lines.append("    condition:")
        lines.append(f"        {condition}")
        
        lines.append("}")
        
        return "\n".join(lines)
    
    def validate_rule(self, rule_content: str) -> bool:
        """Validate YARA rule syntax"""
        is_valid, _ = self.validate_rule_with_error(rule_content)
        return is_valid
    
    def validate_rule_with_error(self, rule_content: str) -> Tuple[bool, Optional[str]]:
        """Validate YARA rule syntax and return error if invalid"""
        if not HAS_YARA:
            return True, None  # Can't validate without yara library
        
        try:
            yara.compile(source=rule_content)
            return True, None
        except yara.SyntaxError as e:
            return False, str(e)
        except Exception as e:
            return False, str(e)
    
    def scan_file(self, rule_content: str, file_path: str) -> List[Dict[str, Any]]:
        """Scan a file with a YARA rule"""
        if not HAS_YARA:
            return []
        
        try:
            rules = yara.compile(source=rule_content)
            matches = rules.match(file_path)
            
            return [
                {
                    "rule": match.rule,
                    "meta": match.meta,
                    "strings": [
                        {
                            "offset": s[0],
                            "identifier": s[1],
                            "data": s[2].decode('utf-8', errors='ignore') if isinstance(s[2], bytes) else s[2]
                        }
                        for s in match.strings
                    ]
                }
                for match in matches
            ]
        except Exception as e:
            print(f"YARA scan error: {e}")
            return []
