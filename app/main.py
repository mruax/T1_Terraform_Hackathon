# app/main.py
"""
FastAPI приложение для анализа логов Terraform
Путь: app/main.py
"""

import json
import logging
import traceback
import hashlib
from datetime import datetime
from contextlib import asynccontextmanager
from typing import List, Dict, Any, Optional

from fastapi import FastAPI, File, UploadFile, HTTPException, Query
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from app.config import PluginConfigLoader
from app.database import DatabaseManager
from app.parser import TerraformLogParser
from app.models import LogLevel

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize config loader and database
config_loader = PluginConfigLoader()
db_manager = DatabaseManager(
    "postgresql://terraform:terraform@postgres:5432/terraform_logs"
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifecycle manager for database connections"""
    await db_manager.connect()
    yield
    await db_manager.disconnect()


# Initialize FastAPI app
app = FastAPI(
    title="Terraform Log Processor API",
    description="Advanced Terraform log analysis with JSON-configured plugins",
    version="3.0.0",
    lifespan=lifespan
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ==================== PYDANTIC MODELS ====================

class LogEntryResponse(BaseModel):
    """Response model for log entry"""
    timestamp: str
    level: str
    message: str
    caller: Optional[str] = None
    module: Optional[str] = None
    section_type: Optional[str] = None
    terraform_metadata: Optional[Dict[str, Any]] = None
    has_http_request: bool = False
    has_http_response: bool = False
    req_id: Optional[str] = None
    rpc: Optional[str] = None


class LogFileInfo(BaseModel):
    """Information about uploaded log file"""
    id: int
    filename: str
    upload_date: str
    total_entries: int
    error_count: int
    warn_count: int


class HealthStatus(BaseModel):
    """System health status"""
    status: str
    total_errors: int
    total_warnings: int
    recent_files: int


# ==================== API ENDPOINTS ====================

@app.get("/")
async def root():
    """Serve main HTML viewer"""
    return FileResponse("terraform_viewer.html")


@app.get("/api/v1/configs", tags=["Configuration"])
async def get_available_configs():
    """Get list of available plugin configurations"""
    return {
        "profiles": list(config_loader.configs.keys()),
        "configs": config_loader.configs
    }


@app.post("/upload-log/", tags=["Logs"])
async def upload_log(
    file: UploadFile = File(...),
    config: str = Query("default", description="Plugin configuration profile")
):
    """
    Upload and parse Terraform log file
    
    Args:
        file: Log file to upload (.log, .txt, .json)
        config: Configuration profile to use (default, production, debug)
    
    Returns:
        Parsed log information including entries, sections, and chains
    """
    logger.info(
        f"Received file upload: {file.filename} with config profile: {config}"
    )
    
    # Validate file type
    if not file.filename.endswith(('.log', '.txt', '.json')):
        raise HTTPException(status_code=400, detail="Invalid file type")
    
    try:
        # Read file content
        content = await file.read()
        logger.info(f"Read {len(content)} bytes from file")
        
        # Calculate file hash for deduplication
        file_hash = hashlib.sha256(content).hexdigest()
        
        # Check if file already exists
        existing_id = await db_manager.file_exists(file_hash)
        if existing_id:
            logger.warning(f"File already exists with id: {existing_id}")
            raise HTTPException(
                status_code=409, 
                detail=f"This file has already been uploaded (File ID: {existing_id})"
            )
        
        # Load plugins from configuration
        plugins = config_loader.create_plugins_from_config(config)
        
        parser = TerraformLogParser(plugins=plugins)
        logger.info(
            f"Parser initialized with {len(plugins)} plugins "
            f"from '{config}' profile"
        )
        
        # Parse lines
        lines = content.decode('utf-8').splitlines()
        logger.info(f"Split into {len(lines)} lines")
        
        entries = []
        parse_errors = 0
        for i, line in enumerate(lines):
            try:
                entry = parser.parse_line(line)
                if entry:
                    entries.append(entry)
            except Exception as e:
                parse_errors += 1
                if parse_errors <= 5:
                    logger.error(
                        f"Error parsing line {i}: {str(e)}\n"
                        f"Line: {line[:100]}"
                    )
        
        logger.info(f"Parsed {len(entries)} entries, {parse_errors} errors")
        
        if len(entries) == 0:
            raise HTTPException(
                status_code=400, 
                detail="No valid log entries found in file"
            )
        
        # Save to database
        logger.info("Attempting to save to database")
        try:
            file_id = await db_manager.save_log_file(
                file.filename, 
                file_hash, 
                entries
            )
            logger.info(f"Saved to database with file_id: {file_id}")
        except Exception as db_error:
            logger.error(f"Database save error: {str(db_error)}")
            logger.error(f"Traceback: {traceback.format_exc()}")
            raise HTTPException(
                status_code=500, 
                detail=f"Database error: {str(db_error)}"
            )
        
        # Build request-response chains
        req_resp_map = {}
        for i, entry in enumerate(entries):
            if entry.req_id:
                if entry.req_id not in req_resp_map:
                    req_resp_map[entry.req_id] = {'indices': []}
                req_resp_map[entry.req_id]['indices'].append(i)
                if entry.http_request:
                    req_resp_map[entry.req_id]['has_request'] = True
                if entry.http_response:
                    req_resp_map[entry.req_id]['has_response'] = True
        
        # Prepare response with first 100 entries
        response_entries = []
        for entry in entries[:100]:
            response_entries.append(LogEntryResponse(
                timestamp=entry.timestamp.isoformat(),
                level=entry.level.name,
                message=entry.message,
                caller=entry.caller,
                module=entry.module,
                section_type=entry.section_type,
                terraform_metadata=entry.terraform_metadata,
                has_http_request=entry.http_request is not None,
                has_http_response=entry.http_response is not None,
                req_id=entry.req_id,
                rpc=entry.rpc
            ))
        
        logger.info("Upload completed successfully")
        return {
            "status": "success",
            "file_id": file_id,
            "total_entries": len(entries),
            "entries": response_entries,
            "sections_detected": list(set(
                e.section_type for e in entries if e.section_type
            )),
            "request_response_chains": len(req_resp_map),
            "plugins_applied": [type(p).__name__ for p in plugins],
            "config_profile": config,
            "parse_errors": parse_errors
        }
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Unexpected error in upload_log: {str(e)}")
        logger.error(f"Traceback: {traceback.format_exc()}")
        raise HTTPException(
            status_code=500, 
            detail=f"Error processing log: {str(e)}"
        )


@app.get("/logs/", response_model=List[LogFileInfo], tags=["Logs"])
async def list_log_files():
    """Get list of all uploaded log files"""
    files = await db_manager.get_log_files()
    return [
        LogFileInfo(
            id=f['id'],
            filename=f['filename'],
            upload_date=f['upload_date'].isoformat(),
            total_entries=f['total_entries'],
            error_count=f['error_count'],
            warn_count=f['warn_count']
        )
        for f in files
    ]


@app.get("/logs/{file_id}", tags=["Logs"])
async def get_log_file(file_id: int):
    """
    Get detailed entries for a specific log file
    
    Args:
        file_id: ID of the log file
        
    Returns:
        Log entries and request chains
    """
    entries = await db_manager.get_log_entries(file_id)
    if not entries:
        raise HTTPException(status_code=404, detail="Log file not found")
    
    # Build request-response chains
    req_chains = {}
    for i, entry in enumerate(entries):
        req_id = entry.get('req_id')
        if req_id:
            if req_id not in req_chains:
                req_chains[req_id] = []
            req_chains[req_id].append(i)
    
    return {
        "file_id": file_id,
        "total_entries": len(entries),
        "entries": entries,
        "request_chains": req_chains
    }


@app.delete("/logs/{file_id}", tags=["Logs"])
async def delete_log_file(file_id: int):
    """Delete a log file and all its entries"""
    await db_manager.delete_log_file(file_id)
    return {"status": "deleted", "file_id": file_id}


# ==================== MONITORING & METRICS ====================

@app.get("/api/v1/health", response_model=HealthStatus, tags=["Monitoring"])
async def get_health_status():
    """Get overall system health status for monitoring integration"""
    files = await db_manager.get_log_files()
    
    total_errors = sum(f['error_count'] for f in files)
    total_warnings = sum(f['warn_count'] for f in files)
    recent_files = len([
        f for f in files 
        if (datetime.now() - f['upload_date']).days < 7
    ])
    
    return HealthStatus(
        status="healthy" if total_errors == 0 else "degraded",
        total_errors=total_errors,
        total_warnings=total_warnings,
        recent_files=recent_files
    )


@app.get("/api/v1/alerts", tags=["Monitoring"])
async def get_alerts(
    severity: str = Query("ERROR", description="ERROR or WARN")
):
    """Get all log entries matching alert severity"""
    files = await db_manager.get_log_files()
    
    all_alerts = []
    for file_info in files:
        entries = await db_manager.get_log_entries(file_info['id'])
        alerts = [e for e in entries if e['level'] == severity]
        
        for alert in alerts:
            all_alerts.append({
                "file_id": file_info['id'],
                "filename": file_info['filename'],
                "timestamp": alert['timestamp'].isoformat(),
                "level": alert['level'],
                "message": alert['message'],
                "section": alert['section_type']
            })
    
    return {
        "severity": severity,
        "count": len(all_alerts),
        "alerts": all_alerts[:50]
    }


@app.get("/api/v1/metrics", tags=["Monitoring"])
async def get_metrics():
    """Get aggregated metrics for monitoring dashboards"""
    files = await db_manager.get_log_files()
    
    metrics = {
        "total_files": len(files),
        "total_logs": sum(f['total_entries'] for f in files),
        "total_errors": sum(f['error_count'] for f in files),
        "total_warnings": sum(f['warn_count'] for f in files),
        "error_rate": 0.0,
        "files_by_date": {}
    }
    
    if metrics["total_logs"] > 0:
        metrics["error_rate"] = (
            metrics["total_errors"] / metrics["total_logs"]
        ) * 100
    
    for f in files:
        date_key = f['upload_date'].date().isoformat()
        if date_key not in metrics["files_by_date"]:
            metrics["files_by_date"][date_key] = 0
        metrics["files_by_date"][date_key] += 1
    
    return metrics


# ==================== GANTT TIMELINE ====================

@app.get("/api/v1/gantt/{file_id}", tags=["Visualization"])
async def get_gantt_data(file_id: int):
    """
    Get Gantt chart data based on actual tf_req_id requests
    
    Returns:
    - requests: List of request objects with req_id, rpc, times, status
    - swimlanes: Grouping by operation type or parallelism
    - dependencies: Links between requests
    - timeline: Absolute time markers
    """
    entries = await db_manager.get_log_entries(file_id)
    if not entries:
        raise HTTPException(status_code=404, detail="Log file not found")
    
    # Group logs by tf_req_id
    requests_map = {}
    
    for idx, entry in enumerate(entries):
        req_id = entry.get('req_id')
        if not req_id:
            continue
        
        if req_id not in requests_map:
            requests_map[req_id] = {
                'req_id': req_id,
                'logs': [],
                'start_time': None,
                'end_time': None,
                'rpc': None,
                'status': 'unknown',
                'error_count': 0,
                'log_indices': []
            }
        
        req = requests_map[req_id]
        req['logs'].append(entry)
        req['log_indices'].append(idx)
        
        # Extract RPC from raw_json
        if entry.get('raw_json'):
            raw = entry['raw_json']
            if isinstance(raw, str):
                try:
                    raw = json.loads(raw)
                except:
                    pass
            
            if isinstance(raw, dict):
                if not req['rpc'] and 'tf_rpc' in raw:
                    req['rpc'] = raw['tf_rpc']
        
        # Track errors
        if entry['level'] == 'ERROR':
            req['error_count'] += 1
    
    # Calculate start/end times and status
    for req_id, req in requests_map.items():
        logs = req['logs']
        if not logs:
            continue
        
        req['start_time'] = min(log['timestamp'] for log in logs)
        req['end_time'] = max(log['timestamp'] for log in logs)
        
        # Determine status
        if req['error_count'] > 0:
            req['status'] = 'error'
        elif any('success' in log['message'].lower() or 
                 'complete' in log['message'].lower() for log in logs):
            req['status'] = 'success'
        elif any('timeout' in log['message'].lower() for log in logs):
            req['status'] = 'timeout'
        else:
            req['status'] = 'running'
    
    # Convert to list and sort by start time
    requests = sorted(
        requests_map.values(), 
        key=lambda r: r['start_time']
    )
    
    requests = [r for r in requests if r['start_time'] and r['end_time']]
    
    if not requests:
        return {
            "file_id": file_id,
            "requests": [],
            "swimlanes": [],
            "timeline": {},
            "summary": {
                "total_requests": 0,
                "total_errors": 0,
                "duration_seconds": 0
            }
        }
    
    # Calculate timeline
    min_time = min(r['start_time'] for r in requests)
    max_time = max(r['end_time'] for r in requests)
    total_duration = (max_time - min_time).total_seconds()
    
    # Assign swimlanes based on parallelism
    swimlanes = []
    for req in requests:
        placed = False
        for lane_idx, lane in enumerate(swimlanes):
            overlaps = False
            for other_req in lane:
                if not (req['end_time'] <= other_req['start_time'] or 
                        req['start_time'] >= other_req['end_time']):
                    overlaps = True
                    break
            
            if not overlaps:
                lane.append(req)
                req['swimlane'] = lane_idx
                placed = True
                break
        
        if not placed:
            swimlanes.append([req])
            req['swimlane'] = len(swimlanes) - 1
    
    # Detect dependencies
    dependencies = []
    for i, req_a in enumerate(requests):
        for j, req_b in enumerate(requests):
            if i >= j:
                continue
            
            time_gap = (req_b['start_time'] - req_a['end_time']).total_seconds()
            if 0 < time_gap < 0.1 and req_a['rpc'] == req_b['rpc']:
                dependencies.append({
                    'from': req_a['req_id'],
                    'to': req_b['req_id'],
                    'type': 'sequential'
                })
    
    # Format response
    formatted_requests = []
    for req in requests:
        duration = (req['end_time'] - req['start_time']).total_seconds()
        formatted_requests.append({
            'req_id': req['req_id'],
            'rpc': req['rpc'] or 'unknown',
            'start_time': req['start_time'].isoformat(),
            'end_time': req['end_time'].isoformat(),
            'duration': duration,
            'status': req['status'],
            'log_count': len(req['logs']),
            'error_count': req['error_count'],
            'swimlane': req['swimlane'],
            'log_indices': req['log_indices']
        })
    
    return {
        "file_id": file_id,
        "requests": formatted_requests,
        "dependencies": dependencies,
        "timeline": {
            "start": min_time.isoformat(),
            "end": max_time.isoformat(),
            "duration_seconds": total_duration,
            "swimlane_count": len(swimlanes)
        },
        "summary": {
            "total_requests": len(requests),
            "total_errors": sum(r['error_count'] for r in requests),
            "duration_seconds": total_duration,
            "parallel_max": len(swimlanes)
        }
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
