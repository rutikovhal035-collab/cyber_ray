"""
Pydantic schemas for API request/response models
"""

from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum


class AnalysisStatus(str, Enum):
    """Analysis task status"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class FileSubmission(BaseModel):
    """File submission response"""
    task_id: str
    filename: str
    status: AnalysisStatus = AnalysisStatus.PENDING
    submitted_at: datetime = Field(default_factory=datetime.utcnow)


class HashInfo(BaseModel):
    """File hash information"""
    md5: str
    sha1: str
    sha256: str
    ssdeep: Optional[str] = None


class PEInfo(BaseModel):
    """PE file information"""
    is_pe: bool = False
    is_dll: bool = False
    is_exe: bool = False
    architecture: Optional[str] = None
    entry_point: Optional[str] = None
    sections: List[Dict[str, Any]] = []
    imports: List[Dict[str, Any]] = []
    exports: List[str] = []


class StaticAnalysisResult(BaseModel):
    """Static analysis results"""
    hashes: HashInfo
    file_size: int
    file_type: str
    pe_info: Optional[PEInfo] = None
    strings: List[str] = []
    suspicious_strings: List[str] = []


class APICall(BaseModel):
    """Single API call trace"""
    timestamp: str
    process_id: int
    process_name: str
    api_name: str
    category: str
    arguments: Dict[str, Any] = {}
    return_value: Optional[str] = None


class ProcessInfo(BaseModel):
    """Process information from dynamic analysis"""
    pid: int
    ppid: int
    name: str
    path: Optional[str] = None
    command_line: Optional[str] = None
    children: List[int] = []


class NetworkActivity(BaseModel):
    """Network activity from dynamic analysis"""
    protocol: str
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    domain: Optional[str] = None


class FileOperation(BaseModel):
    """File operation from dynamic analysis"""
    operation: str  # create, modify, delete, read
    path: str
    process_id: int


class RegistryOperation(BaseModel):
    """Registry operation from dynamic analysis"""
    operation: str  # create, modify, delete, read
    key: str
    value: Optional[str] = None
    data: Optional[str] = None


class DynamicAnalysisResult(BaseModel):
    """Dynamic analysis results"""
    processes: List[ProcessInfo] = []
    api_calls: List[APICall] = []
    network_activity: List[NetworkActivity] = []
    file_operations: List[FileOperation] = []
    registry_operations: List[RegistryOperation] = []
    screenshots: List[str] = []


class BehaviorGraphNode(BaseModel):
    """Node in behavior graph"""
    id: str
    label: str
    type: str  # process, file, network, registry
    properties: Dict[str, Any] = {}


class BehaviorGraphEdge(BaseModel):
    """Edge in behavior graph"""
    source: str
    target: str
    label: str
    properties: Dict[str, Any] = {}


class BehaviorGraph(BaseModel):
    """Full behavior graph data"""
    nodes: List[BehaviorGraphNode] = []
    edges: List[BehaviorGraphEdge] = []


class FullAnalysisReport(BaseModel):
    """Complete analysis report"""
    task_id: str
    filename: str
    status: AnalysisStatus
    submitted_at: datetime
    completed_at: Optional[datetime] = None
    static_analysis: Optional[StaticAnalysisResult] = None
    dynamic_analysis: Optional[DynamicAnalysisResult] = None
    behavior_graph: Optional[BehaviorGraph] = None
    threat_score: int = 0
    threat_level: str = "unknown"  # safe, low, medium, high, critical
    tags: List[str] = []


class YARARule(BaseModel):
    """YARA rule model"""
    id: str
    name: str
    description: str
    rule_content: str
    created_at: datetime = Field(default_factory=datetime.utcnow)
    source_task_id: Optional[str] = None
    tags: List[str] = []


class YARAGenerateRequest(BaseModel):
    """Request to generate YARA rule"""
    task_id: str
    rule_name: Optional[str] = None
    include_strings: bool = True
    include_imports: bool = True
    include_hashes: bool = True
