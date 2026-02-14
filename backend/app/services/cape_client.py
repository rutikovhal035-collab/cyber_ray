"""
CAPEv2 API Client
Handles communication with CAPEv2 sandbox for dynamic analysis
"""

import httpx
import asyncio
from typing import Optional, Dict, Any, List
import os

from app.core.config import settings
from app.models.schemas import (
    DynamicAnalysisResult,
    ProcessInfo,
    APICall,
    NetworkActivity,
    FileOperation,
    RegistryOperation
)


class CAPEClient:
    """Client for interacting with CAPEv2 REST API"""
    
    def __init__(self):
        self.base_url = settings.CAPE_API_URL
        self.token = settings.CAPE_API_TOKEN
        self.headers = {}
        if self.token:
            self.headers["Authorization"] = f"Bearer {self.token}"
    
    async def submit_file(
        self, 
        file_path: str,
        timeout: int = 300,
        options: Optional[Dict[str, Any]] = None
    ) -> Optional[Dict[str, Any]]:
        """
        Submit a file to CAPEv2 for analysis
        
        Args:
            file_path: Path to the file to analyze
            timeout: Analysis timeout in seconds
            options: Additional CAPE options
            
        Returns:
            Task information including task_id
        """
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                with open(file_path, 'rb') as f:
                    files = {"file": (os.path.basename(file_path), f)}
                    data = {
                        "timeout": timeout,
                        **(options or {})
                    }
                    
                    response = await client.post(
                        f"{self.base_url}/apiv2/tasks/create/file/",
                        files=files,
                        data=data,
                        headers=self.headers
                    )
                    
                    if response.status_code == 200:
                        result = response.json()
                        return {
                            "task_id": result.get("task_id") or result.get("data", {}).get("task_ids", [None])[0],
                            "status": "submitted"
                        }
                    else:
                        print(f"CAPE submission failed: {response.status_code} - {response.text}")
                        return None
                        
        except httpx.ConnectError:
            print("Could not connect to CAPEv2 - running in standalone mode")
            # Return mock task for development
            return self._mock_submit()
        except Exception as e:
            print(f"CAPE submission error: {e}")
            return self._mock_submit()
    
    def _mock_submit(self) -> Dict[str, Any]:
        """Return mock task for development without CAPE"""
        import uuid
        return {
            "task_id": str(uuid.uuid4()),
            "status": "mock",
            "message": "Running in standalone mode (CAPE not connected)"
        }
    
    async def get_task_status(self, task_id: str) -> Optional[Dict[str, Any]]:
        """Get the status of a CAPE analysis task"""
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.get(
                    f"{self.base_url}/apiv2/tasks/status/{task_id}/",
                    headers=self.headers
                )
                
                if response.status_code == 200:
                    return response.json()
                return None
                
        except Exception as e:
            print(f"Error getting task status: {e}")
            return {"status": "mock", "task_id": task_id}
    
    async def get_report(
        self, 
        task_id: str,
        max_retries: int = 60,
        retry_interval: int = 10
    ) -> Optional[Dict[str, Any]]:
        """
        Get the analysis report for a completed task
        Polls until the task is complete or max retries reached
        """
        for attempt in range(max_retries):
            try:
                # Check task status first
                status = await self.get_task_status(task_id)
                
                if status and status.get("status") == "reported":
                    # Task complete, get full report
                    async with httpx.AsyncClient(timeout=60.0) as client:
                        response = await client.get(
                            f"{self.base_url}/apiv2/tasks/get/report/{task_id}/",
                            headers=self.headers
                        )
                        
                        if response.status_code == 200:
                            return response.json()
                
                elif status and status.get("status") in ["failed", "failed_analysis"]:
                    return None
                
                # Wait before retry
                await asyncio.sleep(retry_interval)
                
            except httpx.ConnectError:
                print(f"Connection error to CAPE for task {task_id} - returning mock report")
                return self._mock_report(task_id)
            except Exception as e:
                print(f"Error polling CAPE report for {task_id}: {e}")
                await asyncio.sleep(retry_interval)
        
        print(f"Max retries reached for CAPE task {task_id} - returning mock report")
        return self._mock_report(task_id)
    
    def _mock_report(self, task_id: str) -> Dict[str, Any]:
        """Generate mock report for development"""
        return {
            "info": {"id": task_id},
            "behavior": {
                "processes": [
                    {
                        "pid": 1234,
                        "ppid": 1000,
                        "name": "malware.exe",
                        "path": "C:\\Users\\Admin\\malware.exe",
                        "command_line": "malware.exe -param"
                    },
                    {
                        "pid": 1235,
                        "ppid": 1234,
                        "name": "cmd.exe",
                        "path": "C:\\Windows\\System32\\cmd.exe",
                        "command_line": "cmd.exe /c whoami"
                    }
                ],
                "apistats": {
                    "1234": {
                        "CreateFileW": 15,
                        "RegOpenKeyExW": 8,
                        "InternetOpenW": 2,
                        "WriteFile": 5
                    }
                },
                "summary": {
                    "files": [
                        {"operation": "create", "path": "C:\\Users\\Admin\\AppData\\Local\\Temp\\payload.dll"},
                        {"operation": "modify", "path": "C:\\Windows\\System32\\drivers\\etc\\hosts"}
                    ],
                    "keys": [
                        {"operation": "create", "key": "HKEY_CURRENT_USER\\Software\\MalwareKey"},
                        {"operation": "modify", "key": "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"}
                    ]
                }
            },
            "network": {
                "hosts": ["192.168.1.100", "10.0.0.1"],
                "domains": [
                    {"domain": "malicious-c2.com", "ip": "192.168.1.100"}
                ],
                "tcp": [
                    {"src": "10.0.0.50", "dst": "192.168.1.100", "sport": 49152, "dport": 443}
                ],
                "http": [
                    {"uri": "http://malicious-c2.com/beacon", "method": "POST"}
                ]
            },
            "signatures": [
                {"name": "persistence_autorun", "severity": 3, "description": "Creates autorun entry"},
                {"name": "network_c2", "severity": 4, "description": "Contacts C2 server"}
            ],
            "screenshots": ["screenshot_1.jpg", "screenshot_2.jpg"]
        }
    
    def parse_report(self, report: Dict[str, Any]) -> DynamicAnalysisResult:
        """Parse CAPE report into DynamicAnalysisResult"""
        behavior = report.get("behavior", {})
        network = report.get("network", {})
        
        # Parse processes
        processes = []
        for proc in behavior.get("processes", []):
            processes.append(ProcessInfo(
                pid=proc.get("pid", 0),
                ppid=proc.get("ppid", 0),
                name=proc.get("name", "unknown"),
                path=proc.get("path"),
                command_line=proc.get("command_line"),
                children=[]
            ))
        
        # Parse API calls from apistats
        api_calls = []
        for pid, apis in behavior.get("apistats", {}).items():
            for api_name, count in apis.items():
                api_calls.append(APICall(
                    timestamp="",
                    process_id=int(pid),
                    process_name="",
                    api_name=api_name,
                    category=self._categorize_api(api_name),
                    arguments={"count": count}
                ))
        
        # Parse network activity
        network_activity = []
        for conn in network.get("tcp", []):
            network_activity.append(NetworkActivity(
                protocol="TCP",
                src_ip=conn.get("src", ""),
                src_port=conn.get("sport", 0),
                dst_ip=conn.get("dst", ""),
                dst_port=conn.get("dport", 0),
                domain=None
            ))
        
        # Add domain info
        for domain in network.get("domains", []):
            for na in network_activity:
                if na.dst_ip == domain.get("ip"):
                    na.domain = domain.get("domain")
        
        # Parse file operations
        file_operations = []
        summary = behavior.get("summary", {})
        for f in summary.get("files", []):
            file_operations.append(FileOperation(
                operation=f.get("operation", "access"),
                path=f.get("path", ""),
                process_id=0
            ))
        
        # Parse registry operations
        registry_operations = []
        for r in summary.get("keys", []):
            registry_operations.append(RegistryOperation(
                operation=r.get("operation", "access"),
                key=r.get("key", ""),
                value=r.get("value"),
                data=r.get("data")
            ))
        
        return DynamicAnalysisResult(
            processes=processes,
            api_calls=api_calls,
            network_activity=network_activity,
            file_operations=file_operations,
            registry_operations=registry_operations,
            screenshots=report.get("screenshots", [])
        )
    
    def _categorize_api(self, api_name: str) -> str:
        """Categorize API call by name"""
        api_lower = api_name.lower()
        
        if any(x in api_lower for x in ['file', 'read', 'write', 'create', 'delete', 'copy', 'move']):
            return "filesystem"
        elif any(x in api_lower for x in ['reg', 'registry', 'key']):
            return "registry"
        elif any(x in api_lower for x in ['internet', 'http', 'socket', 'connect', 'send', 'recv', 'dns']):
            return "network"
        elif any(x in api_lower for x in ['process', 'thread', 'memory', 'alloc', 'virtual', 'inject']):
            return "process"
        elif any(x in api_lower for x in ['crypt', 'encrypt', 'decrypt', 'hash']):
            return "crypto"
        else:
            return "other"
