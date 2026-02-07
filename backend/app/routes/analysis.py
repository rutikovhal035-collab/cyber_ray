"""
Analysis API Routes
Handles file submission and analysis report retrieval
"""

from fastapi import APIRouter, UploadFile, File, HTTPException, BackgroundTasks
from fastapi.responses import JSONResponse
from typing import List, Optional
import uuid
import os
import aiofiles
from datetime import datetime

from app.models.schemas import (
    FileSubmission, 
    AnalysisStatus, 
    FullAnalysisReport,
    StaticAnalysisResult,
    DynamicAnalysisResult
)
from app.services.cape_client import CAPEClient
from app.services.static_analyzer import StaticAnalyzer
from app.services.graph_builder import BehaviorGraphBuilder
from app.core.config import settings

router = APIRouter()

# In-memory storage for demo (replace with MongoDB in production)
analysis_tasks = {}

cape_client = CAPEClient()
static_analyzer = StaticAnalyzer()
graph_builder = BehaviorGraphBuilder()


async def save_upload_file(upload_file: UploadFile, destination: str):
    """Save uploaded file to disk"""
    os.makedirs(os.path.dirname(destination), exist_ok=True)
    async with aiofiles.open(destination, 'wb') as out_file:
        content = await upload_file.read()
        await out_file.write(content)
    return destination


async def run_analysis(task_id: str, file_path: str):
    """Background task to run full analysis"""
    try:
        # Update status to running
        analysis_tasks[task_id]["status"] = AnalysisStatus.RUNNING
        
        # Run static analysis
        static_result = static_analyzer.analyze(file_path)
        analysis_tasks[task_id]["static_analysis"] = static_result
        
        # Submit to CAPEv2 for dynamic analysis
        cape_task = await cape_client.submit_file(file_path)
        if cape_task:
            analysis_tasks[task_id]["cape_task_id"] = cape_task.get("task_id")
            
            # Poll for results (simplified - in production use Celery)
            report = await cape_client.get_report(cape_task.get("task_id"))
            if report:
                dynamic_result = cape_client.parse_report(report)
                analysis_tasks[task_id]["dynamic_analysis"] = dynamic_result
                
                # Build behavior graph
                behavior_graph = graph_builder.build_graph(
                    static_result, 
                    dynamic_result
                )
                analysis_tasks[task_id]["behavior_graph"] = behavior_graph
        
        # Calculate threat score
        threat_score, threat_level = calculate_threat_score(
            analysis_tasks[task_id].get("static_analysis"),
            analysis_tasks[task_id].get("dynamic_analysis")
        )
        analysis_tasks[task_id]["threat_score"] = threat_score
        analysis_tasks[task_id]["threat_level"] = threat_level
        
        # Mark as completed
        analysis_tasks[task_id]["status"] = AnalysisStatus.COMPLETED
        analysis_tasks[task_id]["completed_at"] = datetime.utcnow()
        
    except Exception as e:
        analysis_tasks[task_id]["status"] = AnalysisStatus.FAILED
        analysis_tasks[task_id]["error"] = str(e)


def calculate_threat_score(static_result, dynamic_result):
    """Calculate threat score based on analysis results"""
    score = 0
    
    if static_result:
        # Check for suspicious strings
        score += len(static_result.get("suspicious_strings", [])) * 5
        
        # Check for packed/obfuscated
        if static_result.get("pe_info", {}).get("is_packed"):
            score += 20
    
    if dynamic_result:
        # Check for network activity
        score += len(dynamic_result.get("network_activity", [])) * 3
        
        # Check for file operations
        score += len([f for f in dynamic_result.get("file_operations", []) 
                     if f.get("operation") == "create"]) * 2
        
        # Check for registry modifications
        score += len([r for r in dynamic_result.get("registry_operations", [])
                     if r.get("operation") in ["create", "modify"]]) * 3
    
    # Determine threat level
    if score < 10:
        level = "safe"
    elif score < 30:
        level = "low"
    elif score < 60:
        level = "medium"
    elif score < 90:
        level = "high"
    else:
        level = "critical"
    
    return min(score, 100), level


@router.post("/submit", response_model=FileSubmission)
async def submit_file(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    timeout: Optional[int] = 300
):
    """
    Submit a file for malware analysis
    
    - **file**: The file to analyze (max 50MB)
    - **timeout**: Analysis timeout in seconds (default 300)
    """
    # Validate file size
    content = await file.read()
    if len(content) > settings.MAX_FILE_SIZE:
        raise HTTPException(
            status_code=413,
            detail=f"File too large. Maximum size is {settings.MAX_FILE_SIZE // (1024*1024)}MB"
        )
    await file.seek(0)  # Reset file position
    
    # Generate task ID
    task_id = str(uuid.uuid4())
    
    # Save file
    file_path = os.path.join(settings.UPLOAD_DIR, task_id, file.filename)
    await save_upload_file(file, file_path)
    
    # Create task entry
    submission = {
        "task_id": task_id,
        "filename": file.filename,
        "file_path": file_path,
        "status": AnalysisStatus.PENDING,
        "submitted_at": datetime.utcnow(),
        "timeout": timeout
    }
    analysis_tasks[task_id] = submission
    
    # Start background analysis
    background_tasks.add_task(run_analysis, task_id, file_path)
    
    return FileSubmission(
        task_id=task_id,
        filename=file.filename,
        status=AnalysisStatus.PENDING
    )


@router.get("/status/{task_id}")
async def get_analysis_status(task_id: str):
    """Get the status of an analysis task"""
    if task_id not in analysis_tasks:
        raise HTTPException(status_code=404, detail="Task not found")
    
    task = analysis_tasks[task_id]
    return {
        "task_id": task_id,
        "status": task["status"],
        "filename": task["filename"],
        "submitted_at": task["submitted_at"],
        "completed_at": task.get("completed_at")
    }


@router.get("/report/{task_id}", response_model=FullAnalysisReport)
async def get_analysis_report(task_id: str):
    """Get the full analysis report for a completed task"""
    if task_id not in analysis_tasks:
        raise HTTPException(status_code=404, detail="Task not found")
    
    task = analysis_tasks[task_id]
    
    if task["status"] == AnalysisStatus.PENDING:
        raise HTTPException(status_code=202, detail="Analysis is pending")
    
    if task["status"] == AnalysisStatus.RUNNING:
        raise HTTPException(status_code=202, detail="Analysis is still running")
    
    if task["status"] == AnalysisStatus.FAILED:
        raise HTTPException(
            status_code=500, 
            detail=f"Analysis failed: {task.get('error', 'Unknown error')}"
        )
    
    return FullAnalysisReport(
        task_id=task_id,
        filename=task["filename"],
        status=task["status"],
        submitted_at=task["submitted_at"],
        completed_at=task.get("completed_at"),
        static_analysis=task.get("static_analysis"),
        dynamic_analysis=task.get("dynamic_analysis"),
        behavior_graph=task.get("behavior_graph"),
        threat_score=task.get("threat_score", 0),
        threat_level=task.get("threat_level", "unknown"),
        tags=task.get("tags", [])
    )


@router.get("/list")
async def list_analyses(
    status: Optional[AnalysisStatus] = None,
    limit: int = 50,
    offset: int = 0
):
    """List all analysis tasks with optional filtering"""
    tasks = list(analysis_tasks.values())
    
    # Filter by status if provided
    if status:
        tasks = [t for t in tasks if t["status"] == status]
    
    # Sort by submitted_at descending
    tasks.sort(key=lambda x: x["submitted_at"], reverse=True)
    
    # Paginate
    total = len(tasks)
    tasks = tasks[offset:offset + limit]
    
    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "tasks": [
            {
                "task_id": t["task_id"],
                "filename": t["filename"],
                "status": t["status"],
                "submitted_at": t["submitted_at"],
                "threat_level": t.get("threat_level", "unknown")
            }
            for t in tasks
        ]
    }


@router.delete("/{task_id}")
async def delete_analysis(task_id: str):
    """Delete an analysis task and its files"""
    if task_id not in analysis_tasks:
        raise HTTPException(status_code=404, detail="Task not found")
    
    task = analysis_tasks[task_id]
    
    # Delete uploaded file
    file_path = task.get("file_path")
    if file_path and os.path.exists(file_path):
        os.remove(file_path)
        # Remove directory if empty
        dir_path = os.path.dirname(file_path)
        if os.path.exists(dir_path) and not os.listdir(dir_path):
            os.rmdir(dir_path)
    
    # Remove from memory
    del analysis_tasks[task_id]
    
    return {"message": f"Task {task_id} deleted successfully"}
