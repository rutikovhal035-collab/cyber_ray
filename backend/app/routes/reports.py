"""
Reports API Routes
Handles report export and statistics
"""

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from typing import Optional
import json
import os
from datetime import datetime, timedelta

router = APIRouter()


@router.get("/export/{task_id}")
async def export_report(task_id: str, format: str = "json"):
    """
    Export analysis report in specified format
    
    - **task_id**: The analysis task ID
    - **format**: Export format (json, html)
    """
    from app.routes.analysis import analysis_tasks
    
    if task_id not in analysis_tasks:
        raise HTTPException(status_code=404, detail="Task not found")
    
    task = analysis_tasks[task_id]
    
    if task["status"] != "completed":
        raise HTTPException(
            status_code=400, 
            detail="Analysis must be completed before exporting"
        )
    
    if format == "json":
        return JSONResponse(
            content=serialize_report(task),
            headers={
                "Content-Disposition": f'attachment; filename="report_{task_id}.json"'
            }
        )
    elif format == "html":
        html_content = generate_html_report(task)
        # Save to temp file and return
        temp_path = f"/tmp/report_{task_id}.html"
        with open(temp_path, 'w') as f:
            f.write(html_content)
        return FileResponse(
            temp_path,
            filename=f"report_{task_id}.html",
            media_type="text/html"
        )
    else:
        raise HTTPException(status_code=400, detail="Unsupported format")


def serialize_report(task):
    """Serialize task data for export"""
    return {
        "task_id": task["task_id"],
        "filename": task["filename"],
        "status": task["status"].value if hasattr(task["status"], 'value') else task["status"],
        "submitted_at": task["submitted_at"].isoformat() if isinstance(task["submitted_at"], datetime) else task["submitted_at"],
        "completed_at": task.get("completed_at").isoformat() if task.get("completed_at") and isinstance(task.get("completed_at"), datetime) else task.get("completed_at"),
        "threat_score": task.get("threat_score", 0),
        "threat_level": task.get("threat_level", "unknown"),
        "static_analysis": task.get("static_analysis"),
        "dynamic_analysis": task.get("dynamic_analysis"),
        "behavior_graph": task.get("behavior_graph")
    }


def generate_html_report(task):
    """Generate HTML report"""
    static = task.get("static_analysis", {})
    dynamic = task.get("dynamic_analysis", {})
    
    html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Malware Analysis Report - {task['filename']}</title>
    <style>
        :root {{
            --bg-primary: #0f172a;
            --bg-secondary: #1e293b;
            --text-primary: #f1f5f9;
            --text-secondary: #94a3b8;
            --accent: #3b82f6;
            --danger: #ef4444;
            --warning: #f59e0b;
            --success: #22c55e;
        }}
        body {{
            font-family: 'Segoe UI', system-ui, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            margin: 0;
            padding: 20px;
            line-height: 1.6;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}
        .header {{
            background: linear-gradient(135deg, var(--bg-secondary) 0%, #334155 100%);
            padding: 30px;
            border-radius: 16px;
            margin-bottom: 24px;
        }}
        .header h1 {{
            margin: 0 0 10px 0;
            font-size: 28px;
        }}
        .threat-badge {{
            display: inline-block;
            padding: 8px 16px;
            border-radius: 8px;
            font-weight: 600;
            text-transform: uppercase;
        }}
        .threat-critical {{ background: var(--danger); }}
        .threat-high {{ background: #dc2626; }}
        .threat-medium {{ background: var(--warning); color: #000; }}
        .threat-low {{ background: #84cc16; color: #000; }}
        .threat-safe {{ background: var(--success); color: #000; }}
        .section {{
            background: var(--bg-secondary);
            padding: 24px;
            border-radius: 12px;
            margin-bottom: 16px;
        }}
        .section h2 {{
            margin-top: 0;
            color: var(--accent);
            border-bottom: 2px solid var(--accent);
            padding-bottom: 10px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
        }}
        th, td {{
            text-align: left;
            padding: 12px;
            border-bottom: 1px solid #334155;
        }}
        th {{
            color: var(--text-secondary);
            font-weight: 500;
        }}
        code {{
            background: #334155;
            padding: 2px 6px;
            border-radius: 4px;
            font-size: 13px;
        }}
        .hash-value {{
            font-family: monospace;
            word-break: break-all;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔬 Malware Analysis Report</h1>
            <p><strong>File:</strong> {task['filename']}</p>
            <p><strong>Task ID:</strong> {task['task_id']}</p>
            <p><strong>Analyzed:</strong> {task.get('completed_at', 'N/A')}</p>
            <span class="threat-badge threat-{task.get('threat_level', 'unknown')}">
                {task.get('threat_level', 'Unknown')} Risk - Score: {task.get('threat_score', 0)}/100
            </span>
        </div>
        
        <div class="section">
            <h2>📊 File Hashes</h2>
            <table>
                <tr><th>Algorithm</th><th>Hash</th></tr>
                <tr><td>MD5</td><td class="hash-value">{static.get('hashes', {}).get('md5', 'N/A')}</td></tr>
                <tr><td>SHA-1</td><td class="hash-value">{static.get('hashes', {}).get('sha1', 'N/A')}</td></tr>
                <tr><td>SHA-256</td><td class="hash-value">{static.get('hashes', {}).get('sha256', 'N/A')}</td></tr>
            </table>
        </div>
        
        <div class="section">
            <h2>📁 File Information</h2>
            <table>
                <tr><th>Property</th><th>Value</th></tr>
                <tr><td>File Size</td><td>{static.get('file_size', 'N/A')} bytes</td></tr>
                <tr><td>File Type</td><td>{static.get('file_type', 'N/A')}</td></tr>
                <tr><td>Architecture</td><td>{static.get('pe_info', {}).get('architecture', 'N/A')}</td></tr>
            </table>
        </div>
        
        <div class="section">
            <h2>🔍 Suspicious Strings</h2>
            <ul>
                {''.join(f'<li><code>{s}</code></li>' for s in static.get('suspicious_strings', [])[:20]) or '<li>No suspicious strings found</li>'}
            </ul>
        </div>
        
        <div class="section">
            <h2>🌐 Network Activity</h2>
            <table>
                <tr><th>Protocol</th><th>Destination</th><th>Port</th><th>Domain</th></tr>
                {''.join(f"<tr><td>{n.get('protocol','')}</td><td>{n.get('dst_ip','')}</td><td>{n.get('dst_port','')}</td><td>{n.get('domain','')}</td></tr>" for n in dynamic.get('network_activity', [])[:20]) or '<tr><td colspan="4">No network activity detected</td></tr>'}
            </table>
        </div>
        
        <footer style="text-align: center; margin-top: 40px; color: var(--text-secondary);">
            Generated by Malware Analysis Sandbox | CyberAy
        </footer>
    </div>
</body>
</html>
"""
    return html


@router.get("/statistics")
async def get_statistics(days: int = 30):
    """Get analysis statistics for the dashboard"""
    from app.routes.analysis import analysis_tasks
    
    cutoff_date = datetime.utcnow() - timedelta(days=days)
    
    # Filter tasks within date range
    recent_tasks = [
        t for t in analysis_tasks.values()
        if t["submitted_at"] >= cutoff_date
    ]
    
    # Calculate statistics
    total = len(recent_tasks)
    completed = len([t for t in recent_tasks if t["status"] == "completed"])
    pending = len([t for t in recent_tasks if t["status"] == "pending"])
    failed = len([t for t in recent_tasks if t["status"] == "failed"])
    
    # Threat level distribution
    threat_levels = {}
    for task in recent_tasks:
        level = task.get("threat_level", "unknown")
        threat_levels[level] = threat_levels.get(level, 0) + 1
    
    # Daily submissions
    daily_submissions = {}
    for task in recent_tasks:
        date_key = task["submitted_at"].strftime("%Y-%m-%d")
        daily_submissions[date_key] = daily_submissions.get(date_key, 0) + 1
    
    return {
        "period_days": days,
        "total_analyses": total,
        "completed": completed,
        "pending": pending,
        "failed": failed,
        "threat_distribution": threat_levels,
        "daily_submissions": daily_submissions,
        "average_threat_score": sum(
            t.get("threat_score", 0) for t in recent_tasks if t["status"] == "completed"
        ) / max(completed, 1)
    }
