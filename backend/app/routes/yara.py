"""
YARA Rule API Routes
Handles YARA rule generation and management
"""

from fastapi import APIRouter, HTTPException, Body
from typing import List, Optional
import uuid
import os
from datetime import datetime

from app.models.schemas import YARARule, YARAGenerateRequest
from app.services.yara_generator import YARAGenerator
from app.core.config import settings

router = APIRouter()

# In-memory storage for rules (replace with MongoDB in production)
yara_rules = {}

yara_generator = YARAGenerator()


@router.post("/generate", response_model=YARARule)
async def generate_yara_rule(request: YARAGenerateRequest):
    """
    Generate a YARA rule from analysis results
    
    - **task_id**: The analysis task ID to generate rule from
    - **rule_name**: Optional custom name for the rule
    - **include_strings**: Include suspicious strings in rule
    - **include_imports**: Include suspicious imports in rule
    - **include_hashes**: Include file hashes in rule metadata
    """
    # Import here to avoid circular dependency
    from app.routes.analysis import analysis_tasks
    
    if request.task_id not in analysis_tasks:
        raise HTTPException(status_code=404, detail="Analysis task not found")
    
    task = analysis_tasks[request.task_id]
    
    if task["status"] != "completed":
        raise HTTPException(
            status_code=400, 
            detail="Analysis must be completed before generating YARA rule"
        )
    
    # Generate YARA rule
    rule_content = yara_generator.generate_rule(
        task_id=request.task_id,
        static_analysis=task.get("static_analysis"),
        dynamic_analysis=task.get("dynamic_analysis"),
        rule_name=request.rule_name,
        include_strings=request.include_strings,
        include_imports=request.include_imports,
        include_hashes=request.include_hashes
    )
    
    # Create rule entry
    rule_id = str(uuid.uuid4())
    rule_name = request.rule_name or f"rule_{request.task_id[:8]}"
    
    rule = YARARule(
        id=rule_id,
        name=rule_name,
        description=f"Auto-generated rule from analysis of {task['filename']}",
        rule_content=rule_content,
        source_task_id=request.task_id,
        tags=task.get("tags", [])
    )
    
    yara_rules[rule_id] = rule.model_dump()
    
    # Save to file
    await save_rule_to_file(rule)
    
    return rule


async def save_rule_to_file(rule: YARARule):
    """Save YARA rule to file system"""
    os.makedirs(settings.YARA_RULES_DIR, exist_ok=True)
    file_path = os.path.join(settings.YARA_RULES_DIR, f"{rule.name}.yar")
    
    with open(file_path, 'w') as f:
        f.write(rule.rule_content)


@router.get("/rules", response_model=List[YARARule])
async def list_yara_rules(
    limit: int = 50,
    offset: int = 0
):
    """List all saved YARA rules"""
    rules = list(yara_rules.values())
    rules.sort(key=lambda x: x["created_at"], reverse=True)
    
    return [YARARule(**r) for r in rules[offset:offset + limit]]


@router.get("/rules/{rule_id}", response_model=YARARule)
async def get_yara_rule(rule_id: str):
    """Get a specific YARA rule by ID"""
    if rule_id not in yara_rules:
        raise HTTPException(status_code=404, detail="Rule not found")
    
    return YARARule(**yara_rules[rule_id])


@router.put("/rules/{rule_id}", response_model=YARARule)
async def update_yara_rule(
    rule_id: str,
    name: Optional[str] = None,
    description: Optional[str] = None,
    rule_content: Optional[str] = None,
    tags: Optional[List[str]] = None
):
    """Update an existing YARA rule"""
    if rule_id not in yara_rules:
        raise HTTPException(status_code=404, detail="Rule not found")
    
    rule = yara_rules[rule_id]
    
    if name:
        rule["name"] = name
    if description:
        rule["description"] = description
    if rule_content:
        rule["rule_content"] = rule_content
        # Validate YARA syntax
        if not yara_generator.validate_rule(rule_content):
            raise HTTPException(status_code=400, detail="Invalid YARA rule syntax")
    if tags:
        rule["tags"] = tags
    
    yara_rules[rule_id] = rule
    
    # Update file
    updated_rule = YARARule(**rule)
    await save_rule_to_file(updated_rule)
    
    return updated_rule


@router.delete("/rules/{rule_id}")
async def delete_yara_rule(rule_id: str):
    """Delete a YARA rule"""
    if rule_id not in yara_rules:
        raise HTTPException(status_code=404, detail="Rule not found")
    
    rule = yara_rules[rule_id]
    
    # Delete file
    file_path = os.path.join(settings.YARA_RULES_DIR, f"{rule['name']}.yar")
    if os.path.exists(file_path):
        os.remove(file_path)
    
    del yara_rules[rule_id]
    
    return {"message": f"Rule {rule_id} deleted successfully"}


@router.post("/validate")
async def validate_yara_rule(rule_content: str = Body(..., embed=True)):
    """Validate YARA rule syntax"""
    is_valid, error = yara_generator.validate_rule_with_error(rule_content)
    
    return {
        "valid": is_valid,
        "error": error
    }


@router.post("/test/{rule_id}")
async def test_yara_rule(rule_id: str, task_id: str):
    """Test a YARA rule against a previously analyzed sample"""
    if rule_id not in yara_rules:
        raise HTTPException(status_code=404, detail="Rule not found")
    
    from app.routes.analysis import analysis_tasks
    
    if task_id not in analysis_tasks:
        raise HTTPException(status_code=404, detail="Analysis task not found")
    
    task = analysis_tasks[task_id]
    rule = yara_rules[rule_id]
    
    # Test rule against file
    matches = yara_generator.scan_file(
        rule["rule_content"], 
        task.get("file_path")
    )
    
    return {
        "rule_id": rule_id,
        "task_id": task_id,
        "matches": matches,
        "matched": len(matches) > 0
    }
