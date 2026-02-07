"""
Static Analysis Module
Performs static analysis on files without execution
"""

import hashlib
import os
import re
from typing import Dict, List, Any, Optional, Tuple

# Optional imports - gracefully handle if not installed
try:
    import pefile
    HAS_PEFILE = True
except ImportError:
    HAS_PEFILE = False
    print("Warning: pefile not installed. PE analysis will be limited.")

try:
    import ssdeep
    HAS_SSDEEP = True
except ImportError:
    HAS_SSDEEP = False
    print("Warning: ssdeep not installed. Fuzzy hashing disabled.")

try:
    import magic
    HAS_MAGIC = True
except ImportError:
    HAS_MAGIC = False
    print("Warning: python-magic not installed. File type detection limited.")


class StaticAnalyzer:
    """Performs static analysis on files"""
    
    # Suspicious string patterns for malware detection
    SUSPICIOUS_PATTERNS = [
        # URLs and IPs
        r'https?://[^\s<>"{}|\\^`\[\]]+',
        r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',
        
        # File paths
        r'C:\\Windows\\System32',
        r'C:\\Users\\.*\\AppData',
        r'\\Temp\\',
        
        # Registry keys
        r'HKEY_LOCAL_MACHINE',
        r'HKEY_CURRENT_USER',
        r'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
        
        # Suspicious commands
        r'cmd\.exe',
        r'powershell',
        r'wscript',
        r'cscript',
        r'regsvr32',
        r'rundll32',
        r'mshta',
        r'certutil',
        
        # Encoding/Obfuscation
        r'base64',
        r'FromBase64String',
        r'-enc',
        r'-encoded',
        
        # Network related
        r'WinHttpRequest',
        r'XMLHTTP',
        r'InternetOpen',
        r'socket',
        r'recv',
        r'send',
        
        # Crypto
        r'CryptEncrypt',
        r'CryptDecrypt',
        r'AES',
        r'RSA',
        
        # Injection
        r'VirtualAlloc',
        r'WriteProcessMemory',
        r'CreateRemoteThread',
        r'NtCreateThread',
        
        # Persistence
        r'schtasks',
        r'at\.exe',
        r'startup',
    ]
    
    # Suspicious API imports
    SUSPICIOUS_IMPORTS = [
        'VirtualAlloc', 'VirtualAllocEx', 'VirtualProtect',
        'WriteProcessMemory', 'ReadProcessMemory',
        'CreateRemoteThread', 'NtCreateThreadEx',
        'OpenProcess', 'CreateProcess',
        'LoadLibrary', 'GetProcAddress',
        'RegSetValueEx', 'RegCreateKeyEx',
        'InternetOpen', 'InternetConnect', 'HttpSendRequest',
        'WSASocket', 'connect', 'send', 'recv',
        'CryptEncrypt', 'CryptDecrypt',
        'IsDebuggerPresent', 'CheckRemoteDebuggerPresent',
        'GetTickCount', 'QueryPerformanceCounter',
        'SetWindowsHookEx', 'GetAsyncKeyState'
    ]
    
    def analyze(self, file_path: str) -> Dict[str, Any]:
        """
        Perform complete static analysis on a file
        
        Args:
            file_path: Path to file to analyze
            
        Returns:
            Dictionary containing all static analysis results
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")
        
        with open(file_path, 'rb') as f:
            file_data = f.read()
        
        # Calculate hashes
        hashes = self._calculate_hashes(file_data)
        
        # Get file info
        file_size = len(file_data)
        file_type = self._detect_file_type(file_path, file_data)
        
        # Extract strings
        strings = self._extract_strings(file_data)
        suspicious_strings = self._find_suspicious_strings(strings)
        
        # PE analysis if applicable
        pe_info = None
        if self._is_pe_file(file_data):
            pe_info = self._analyze_pe(file_path, file_data)
        
        return {
            "hashes": hashes,
            "file_size": file_size,
            "file_type": file_type,
            "pe_info": pe_info,
            "strings": strings[:500],  # Limit to first 500
            "suspicious_strings": suspicious_strings
        }
    
    def _calculate_hashes(self, data: bytes) -> Dict[str, str]:
        """Calculate multiple hash types for the file"""
        hashes = {
            "md5": hashlib.md5(data).hexdigest(),
            "sha1": hashlib.sha1(data).hexdigest(),
            "sha256": hashlib.sha256(data).hexdigest()
        }
        
        if HAS_SSDEEP:
            try:
                hashes["ssdeep"] = ssdeep.hash(data)
            except:
                hashes["ssdeep"] = None
        
        return hashes
    
    def _detect_file_type(self, file_path: str, data: bytes) -> str:
        """Detect the file type"""
        if HAS_MAGIC:
            try:
                return magic.from_buffer(data)
            except:
                pass
        
        # Fallback detection based on magic bytes
        magic_bytes = {
            b'MZ': 'Windows Executable (PE)',
            b'PK': 'ZIP Archive / Office Document',
            b'\x7fELF': 'Linux Executable (ELF)',
            b'%PDF': 'PDF Document',
            b'\xd0\xcf\x11\xe0': 'Microsoft Office Document (OLE)',
            b'Rar!': 'RAR Archive',
            b'\x1f\x8b': 'GZIP Archive',
        }
        
        for signature, file_type in magic_bytes.items():
            if data.startswith(signature):
                return file_type
        
        # Check extension as fallback
        ext = os.path.splitext(file_path)[1].lower()
        ext_types = {
            '.exe': 'Windows Executable',
            '.dll': 'Windows DLL',
            '.pdf': 'PDF Document',
            '.doc': 'Word Document',
            '.docx': 'Word Document',
            '.xls': 'Excel Spreadsheet',
            '.xlsx': 'Excel Spreadsheet',
            '.js': 'JavaScript',
            '.vbs': 'VBScript',
            '.ps1': 'PowerShell Script',
            '.bat': 'Batch Script',
        }
        
        return ext_types.get(ext, 'Unknown')
    
    def _is_pe_file(self, data: bytes) -> bool:
        """Check if file is a PE (Windows executable)"""
        return data[:2] == b'MZ'
    
    def _analyze_pe(self, file_path: str, data: bytes) -> Dict[str, Any]:
        """Analyze PE file structure"""
        if not HAS_PEFILE:
            return {
                "is_pe": True,
                "error": "pefile library not installed"
            }
        
        try:
            pe = pefile.PE(data=data)
            
            # Basic info
            pe_info = {
                "is_pe": True,
                "is_dll": hasattr(pe, "DIRECTORY_ENTRY_EXPORT"),
                "is_exe": not hasattr(pe, "DIRECTORY_ENTRY_EXPORT"),
                "architecture": "x64" if pe.OPTIONAL_HEADER.Magic == 0x20b else "x86",
                "entry_point": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
                "image_base": hex(pe.OPTIONAL_HEADER.ImageBase),
                "subsystem": self._get_subsystem_name(pe.OPTIONAL_HEADER.Subsystem),
                "compile_time": None,
                "sections": [],
                "imports": [],
                "exports": [],
                "suspicious_imports": [],
                "is_packed": False
            }
            
            # Timestamp
            try:
                import datetime
                pe_info["compile_time"] = datetime.datetime.fromtimestamp(
                    pe.FILE_HEADER.TimeDateStamp
                ).isoformat()
            except:
                pass
            
            # Sections
            for section in pe.sections:
                section_name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
                section_info = {
                    "name": section_name,
                    "virtual_address": hex(section.VirtualAddress),
                    "virtual_size": section.Misc_VirtualSize,
                    "raw_size": section.SizeOfRawData,
                    "entropy": section.get_entropy(),
                    "characteristics": hex(section.Characteristics)
                }
                pe_info["sections"].append(section_info)
                
                # High entropy suggests packing/encryption
                if section.get_entropy() > 7.0:
                    pe_info["is_packed"] = True
            
            # Imports
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = entry.dll.decode('utf-8', errors='ignore')
                    dll_imports = {
                        "dll": dll_name,
                        "functions": []
                    }
                    
                    for imp in entry.imports:
                        if imp.name:
                            func_name = imp.name.decode('utf-8', errors='ignore')
                            dll_imports["functions"].append(func_name)
                            
                            # Check for suspicious imports
                            if func_name in self.SUSPICIOUS_IMPORTS:
                                pe_info["suspicious_imports"].append(f"{dll_name}:{func_name}")
                    
                    pe_info["imports"].append(dll_imports)
            
            # Exports
            if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
                for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    if exp.name:
                        pe_info["exports"].append(exp.name.decode('utf-8', errors='ignore'))
            
            pe.close()
            return pe_info
            
        except Exception as e:
            return {
                "is_pe": True,
                "error": str(e)
            }
    
    def _get_subsystem_name(self, subsystem: int) -> str:
        """Convert PE subsystem number to name"""
        subsystems = {
            0: "Unknown",
            1: "Native",
            2: "Windows GUI",
            3: "Windows Console",
            5: "OS/2 Console",
            7: "POSIX Console",
            9: "Windows CE GUI",
            10: "EFI Application",
            11: "EFI Boot Driver",
            12: "EFI Runtime Driver",
            13: "EFI ROM",
            14: "Xbox",
            16: "Windows Boot Application"
        }
        return subsystems.get(subsystem, f"Unknown ({subsystem})")
    
    def _extract_strings(self, data: bytes, min_length: int = 4) -> List[str]:
        """Extract printable strings from binary data"""
        # ASCII strings
        ascii_pattern = rb'[\x20-\x7e]{%d,}' % min_length
        ascii_strings = re.findall(ascii_pattern, data)
        
        # Unicode strings (UTF-16LE common in Windows)
        unicode_pattern = rb'(?:[\x20-\x7e]\x00){%d,}' % min_length
        unicode_matches = re.findall(unicode_pattern, data)
        unicode_strings = [s.decode('utf-16le', errors='ignore') for s in unicode_matches]
        
        all_strings = [s.decode('ascii', errors='ignore') for s in ascii_strings]
        all_strings.extend(unicode_strings)
        
        # Remove duplicates while preserving order
        seen = set()
        unique_strings = []
        for s in all_strings:
            s = s.strip()
            if s and s not in seen:
                seen.add(s)
                unique_strings.append(s)
        
        return unique_strings
    
    def _find_suspicious_strings(self, strings: List[str]) -> List[str]:
        """Find strings matching suspicious patterns"""
        suspicious = []
        
        for string in strings:
            for pattern in self.SUSPICIOUS_PATTERNS:
                if re.search(pattern, string, re.IGNORECASE):
                    if string not in suspicious:
                        suspicious.append(string)
                    break
        
        return suspicious[:100]  # Limit to 100 suspicious strings
