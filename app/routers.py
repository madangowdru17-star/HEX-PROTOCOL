from fastapi import APIRouter, Depends, HTTPException, Request, status, Query, Form
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from sqlalchemy import desc
from typing import Optional
from datetime import datetime, timedelta
import time
import uuid

from app.database import get_db
from app.models import (
    AdminUser, Application, License, Device, IPBan, DeviceBan,
    APIRequestLog, SecurityEvent, AdminAuditLog, LicenseStatus
)
from app.security import (
    verify_password, get_password_hash, create_access_token,
    decode_access_token, hash_api_key, generate_api_key, sign_data
)
from app.utils import generate_license_key, calculate_expiry, verify_license
from app.deps import get_current_admin, get_client_ip
from app.config import settings

router = APIRouter()
templates = Jinja2Templates(directory="templates")

# ==================== ADMIN AUTH ====================

@router.post("/admin/api/auth/login")
async def admin_login(
    username: str = Form(...),
    password: str = Form(...),
    request: Request = None,
    db: Session = Depends(get_db)
):
    admin = db.query(AdminUser).filter(AdminUser.username == username).first()
    if not admin or not verify_password(password, admin.hashed_password):
        ip = get_client_ip(request) if request else "unknown"
        event = SecurityEvent(
            event_type="failed_login",
            description=f"Failed login attempt for user: {username}",
            ip_address=ip
        )
        db.add(event)
        db.commit()
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    admin.last_login = datetime.utcnow()
    db.commit()
    token = create_access_token(data={"sub": str(admin.id)})
    return {"access_token": token, "token_type": "bearer"}

# ==================== ADMIN PAGES ====================

@router.get("/admin/login", response_class=HTMLResponse)
async def admin_login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

@router.get("/admin", response_class=HTMLResponse)
@router.get("/admin/dashboard", response_class=HTMLResponse)
async def admin_dashboard_page(request: Request, db: Session = Depends(get_db)):
    total_keys = db.query(License).count()
    active_keys = db.query(License).filter(License.status == LicenseStatus.ACTIVE).count()
    expired_keys = db.query(License).filter(License.status == LicenseStatus.EXPIRED).count()
    banned_keys = db.query(License).filter(License.status == LicenseStatus.BANNED).count()
    revoked_keys = db.query(License).filter(License.status == LicenseStatus.REVOKED).count()
    total_devices = db.query(Device).count()
    api_requests = db.query(APIRequestLog).count()
    failed_requests = db.query(APIRequestLog).filter(APIRequestLog.is_success == False).count()
    security_events = db.query(SecurityEvent).count()
    
    stats = {
        "total_keys": total_keys,
        "active_keys": active_keys,
        "expired_keys": expired_keys,
        "banned_keys": banned_keys,
        "revoked_keys": revoked_keys,
        "total_devices": total_devices,
        "api_requests": api_requests,
        "failed_requests": failed_requests,
        "security_events": security_events,
    }
    return templates.TemplateResponse("dashboard.html", {"request": request, "stats": stats})

@router.get("/admin/keys", response_class=HTMLResponse)
async def admin_keys_page(request: Request):
    return templates.TemplateResponse("keys.html", {"request": request})

@router.get("/admin/apps", response_class=HTMLResponse)
async def admin_apps_page(request: Request):
    return templates.TemplateResponse("apps.html", {"request": request})

@router.get("/admin/devices", response_class=HTMLResponse)
async def admin_devices_page(request: Request):
    return templates.TemplateResponse("devices.html", {"request": request})

@router.get("/admin/bans", response_class=HTMLResponse)
async def admin_bans_page(request: Request):
    return templates.TemplateResponse("bans.html", {"request": request})

@router.get("/admin/logs", response_class=HTMLResponse)
async def admin_logs_page(request: Request):
    return templates.TemplateResponse("logs.html", {"request": request})

@router.get("/admin/settings", response_class=HTMLResponse)
async def admin_settings_page(request: Request):
    return templates.TemplateResponse("settings.html", {"request": request})

# ==================== ADMIN API - KEYS ====================

@router.get("/admin/api/keys")
async def admin_list_keys(
    admin: AdminUser = Depends(get_current_admin),
    db: Session = Depends(get_db)
):
    keys = db.query(License).order_by(desc(License.created_at)).all()
    return [
        {
            "id": k.id,
            "key": k.key,
            "status": k.status.value if hasattr(k.status, 'value') else str(k.status),
            "app_id": k.application_id,
            "app_name": k.application.name if k.application else "",
            "max_devices": k.max_devices,
            "expires_at": k.expires_at.isoformat() if k.expires_at else None,
            "created_at": k.created_at.isoformat() if k.created_at else None
        }
        for k in keys
    ]

@router.post("/admin/api/keys")
async def admin_create_key(
    application_id: int = Form(...),
    max_devices: int = Form(1),
    hours: Optional[int] = Form(None),
    days: Optional[int] = Form(None),
    expires_at: Optional[str] = Form(None),
    is_permanent: bool = Form(False),
    quantity: int = Form(1),
    admin: AdminUser = Depends(get_current_admin),
    db: Session = Depends(get_db)
):
    app = db.query(Application).filter(Application.id == application_id).first()
    if not app:
        raise HTTPException(status_code=404, detail="Application not found")
    
    expiry_date = None
    if expires_at:
        try:
            expiry_date = datetime.fromisoformat(expires_at)
        except:
            raise HTTPException(status_code=400, detail="Invalid expiry date format")
    
    created_keys = []
    for _ in range(quantity):
        key = generate_license_key()
        expiry = calculate_expiry(hours=hours, days=days, expires_at=expiry_date, is_permanent=is_permanent)
        new_license = License(
            key=key,
            application_id=application_id,
            max_devices=max_devices,
            expires_at=expiry,
            status=LicenseStatus.UNUSED
        )
        db.add(new_license)
        db.commit()
        db.refresh(new_license)
        created_keys.append({
            "id": new_license.id,
            "key": new_license.key,
            "status": new_license.status.value,
            "expires_at": new_license.expires_at.isoformat() if new_license.expires_at else None
        })
    
    audit = AdminAuditLog(
        admin_user_id=admin.id,
        action="create_keys",
        details=f"Created {quantity} key(s) for app {app.name}"
    )
    db.add(audit)
    db.commit()
    
    return {"keys": created_keys}

@router.put("/admin/api/keys/{key_id}/status")
async def admin_update_key_status(
    key_id: int,
    status: str = Form(...),
    admin: AdminUser = Depends(get_current_admin),
    db: Session = Depends(get_db)
):
    license_obj = db.query(License).filter(License.id == key_id).first()
    if not license_obj:
        raise HTTPException(status_code=404, detail="License not found")
    
    try:
        new_status = LicenseStatus[status.upper()]
    except KeyError:
        raise HTTPException(status_code=400, detail="Invalid status")
    
    license_obj.status = new_status
    db.commit()
    
    audit = AdminAuditLog(
        admin_user_id=admin.id,
        action="update_key_status",
        details=f"Changed key {license_obj.key} status to {new_status.value}"
    )
    db.add(audit)
    db.commit()
    
    return {"message": "Status updated", "status": new_status.value}

@router.delete("/admin/api/keys/{key_id}")
async def admin_delete_key(
    key_id: int,
    admin: AdminUser = Depends(get_current_admin),
    db: Session = Depends(get_db)
):
    license_obj = db.query(License).filter(License.id == key_id).first()
    if not license_obj:
        raise HTTPException(status_code=404, detail="License not found")
    
    db.delete(license_obj)
    db.commit()
    
    audit = AdminAuditLog(
        admin_user_id=admin.id,
        action="delete_key",
        details=f"Deleted key {license_obj.key}"
    )
    db.add(audit)
    db.commit()
    
    return {"message": "Key deleted"}

# ==================== ADMIN API - APPLICATIONS ====================

@router.get("/admin/api/apps")
async def admin_list_apps(
    admin: AdminUser = Depends(get_current_admin),
    db: Session = Depends(get_db)
):
    apps = db.query(Application).order_by(desc(Application.created_at)).all()
    return [
        {
            "id": a.id,
            "name": a.name,
            "description": a.description,
            "is_active": a.is_active,
            "created_at": a.created_at.isoformat() if a.created_at else None,
            "license_count": len(a.licenses)
        }
        for a in apps
    ]

@router.post("/admin/api/apps")
async def admin_create_app(
    name: str = Form(...),
    description: str = Form(None),
    admin: AdminUser = Depends(get_current_admin),
    db: Session = Depends(get_db)
):
    existing = db.query(Application).filter(Application.name == name).first()
    if existing:
        raise HTTPException(status_code=400, detail="Application name already exists")
    
    api_key = generate_api_key()
    api_key_hash = hash_api_key(api_key)
    app = Application(name=name, description=description, api_key_hash=api_key_hash, is_active=True)
    db.add(app)
    db.commit()
    db.refresh(app)
    
    audit = AdminAuditLog(
        admin_user_id=admin.id,
        action="create_app",
        details=f"Created application: {name}"
    )
    db.add(audit)
    db.commit()
    
    return {"id": app.id, "name": app.name, "api_key": api_key}

@router.put("/admin/api/apps/{app_id}/toggle")
async def admin_toggle_app(
    app_id: int,
    admin: AdminUser = Depends(get_current_admin),
    db: Session = Depends(get_db)
):
    app = db.query(Application).filter(Application.id == app_id).first()
    if not app:
        raise HTTPException(status_code=404, detail="App not found")
    
    app.is_active = not app.is_active
    db.commit()
    
    audit = AdminAuditLog(
        admin_user_id=admin.id,
        action="toggle_app",
        details=f"{'Activated' if app.is_active else 'Deactivated'} app: {app.name}"
    )
    db.add(audit)
    db.commit()
    
    return {"is_active": app.is_active}

# ==================== ADMIN API - DEVICES ====================

@router.get("/admin/api/devices")
async def admin_list_devices(
    admin: AdminUser = Depends(get_current_admin),
    db: Session = Depends(get_db)
):
    devices = db.query(Device).order_by(desc(Device.last_seen)).all()
    return [
        {
            "id": d.id,
            "device_id": d.device_id,
            "license_id": d.license_id,
            "license_key": d.license.key if d.license else "",
            "ip_address": d.ip_address,
            "last_seen": d.last_seen.isoformat() if d.last_seen else None,
            "is_banned": d.is_banned
        }
        for d in devices
    ]

@router.put("/admin/api/devices/{device_id}/ban")
async def admin_ban_device(
    device_id: str,
    reason: str = Form(None),
    is_permanent: bool = Form(True),
    expires_at: Optional[str] = Form(None),
    admin: AdminUser = Depends(get_current_admin),
    db: Session = Depends(get_db)
):
    device = db.query(Device).filter(Device.device_id == device_id).first()
    if device:
        device.is_banned = True
    
    expiry = None
    if expires_at:
        try:
            expiry = datetime.fromisoformat(expires_at)
        except:
            raise HTTPException(status_code=400, detail="Invalid expiry date")
    
    existing_ban = db.query(DeviceBan).filter(DeviceBan.device_id == device_id).first()
    if existing_ban:
        existing_ban.reason = reason
        existing_ban.is_permanent = is_permanent
        existing_ban.expires_at = expiry
    else:
        ban = DeviceBan(device_id=device_id, reason=reason, is_permanent=is_permanent, expires_at=expiry)
        db.add(ban)
    
    db.commit()
    
    audit = AdminAuditLog(
        admin_user_id=admin.id,
        action="ban_device",
        details=f"Banned device: {device_id}"
    )
    db.add(audit)
    db.commit()
    
    return {"message": "Device banned"}

@router.put("/admin/api/devices/{device_id}/unban")
async def admin_unban_device(
    device_id: str,
    admin: AdminUser = Depends(get_current_admin),
    db: Session = Depends(get_db)
):
    device = db.query(Device).filter(Device.device_id == device_id).first()
    if device:
        device.is_banned = False
    
    db.query(DeviceBan).filter(DeviceBan.device_id == device_id).delete()
    db.commit()
    
    audit = AdminAuditLog(
        admin_user_id=admin.id,
        action="unban_device",
        details=f"Unbanned device: {device_id}"
    )
    db.add(audit)
    db.commit()
    
    return {"message": "Device unbanned"}

# ==================== ADMIN API - BANS ====================

@router.get("/admin/api/ip-bans")
async def admin_list_ip_bans(
    admin: AdminUser = Depends(get_current_admin),
    db: Session = Depends(get_db)
):
    bans = db.query(IPBan).order_by(desc(IPBan.created_at)).all()
    return [
        {
            "id": b.id,
            "ip_address": b.ip_address,
            "reason": b.reason,
            "is_permanent": b.is_permanent,
            "expires_at": b.expires_at.isoformat() if b.expires_at else None,
            "created_at": b.created_at.isoformat() if b.created_at else None
        }
        for b in bans
    ]

@router.post("/admin/api/ip-bans")
async def admin_create_ip_ban(
    ip_address: str = Form(...),
    reason: str = Form(None),
    is_permanent: bool = Form(True),
    expires_at: Optional[str] = Form(None),
    admin: AdminUser = Depends(get_current_admin),
    db: Session = Depends(get_db)
):
    expiry = None
    if expires_at:
        try:
            expiry = datetime.fromisoformat(expires_at)
        except:
            raise HTTPException(status_code=400, detail="Invalid expiry date")
    
    existing = db.query(IPBan).filter(IPBan.ip_address == ip_address).first()
    if existing:
        existing.reason = reason
        existing.is_permanent = is_permanent
        existing.expires_at = expiry
    else:
        ban = IPBan(ip_address=ip_address, reason=reason, is_permanent=is_permanent, expires_at=expiry)
        db.add(ban)
    
    db.commit()
    
    audit = AdminAuditLog(
        admin_user_id=admin.id,
        action="ban_ip",
        details=f"Banned IP: {ip_address}"
    )
    db.add(audit)
    db.commit()
    
    return {"message": "IP banned"}

@router.delete("/admin/api/ip-bans/{ban_id}")
async def admin_delete_ip_ban(
    ban_id: int,
    admin: AdminUser = Depends(get_current_admin),
    db: Session = Depends(get_db)
):
    ban = db.query(IPBan).filter(IPBan.id == ban_id).first()
    if ban:
        db.delete(ban)
        db.commit()
    
    return {"message": "Ban removed"}

@router.get("/admin/api/device-bans")
async def admin_list_device_bans(
    admin: AdminUser = Depends(get_current_admin),
    db: Session = Depends(get_db)
):
    bans = db.query(DeviceBan).order_by(desc(DeviceBan.created_at)).all()
    return [
        {
            "id": b.id,
            "device_id": b.device_id,
            "reason": b.reason,
            "is_permanent": b.is_permanent,
            "expires_at": b.expires_at.isoformat() if b.expires_at else None,
            "created_at": b.created_at.isoformat() if b.created_at else None
        }
        for b in bans
    ]

# ==================== ADMIN API - LOGS ====================

@router.get("/admin/api/logs")
async def admin_get_logs(
    log_type: str = Query("api"),
    limit: int = Query(100),
    admin: AdminUser = Depends(get_current_admin),
    db: Session = Depends(get_db)
):
    if log_type == "api":
        logs = db.query(APIRequestLog).order_by(desc(APIRequestLog.created_at)).limit(limit).all()
        return [
            {
                "id": l.id,
                "request_id": l.request_id,
                "application_id": l.application_id,
                "license_key": l.license_key,
                "device_id": l.device_id,
                "ip_address": l.ip_address,
                "endpoint": l.endpoint,
                "method": l.method,
                "status_code": l.status_code,
                "is_success": l.is_success,
                "error_message": l.error_message,
                "created_at": l.created_at.isoformat() if l.created_at else None
            }
            for l in logs
        ]
    elif log_type == "security":
        logs = db.query(SecurityEvent).order_by(desc(SecurityEvent.created_at)).limit(limit).all()
        return [
            {
                "id": l.id,
                "event_type": l.event_type,
                "description": l.description,
                "ip_address": l.ip_address,
                "user_agent": l.user_agent,
                "created_at": l.created_at.isoformat() if l.created_at else None
            }
            for l in logs
        ]
    elif log_type == "audit":
        logs = db.query(AdminAuditLog).order_by(desc(AdminAuditLog.created_at)).limit(limit).all()
        return [
            {
                "id": l.id,
                "admin_user_id": l.admin_user_id,
                "action": l.action,
                "details": l.details,
                "ip_address": l.ip_address,
                "created_at": l.created_at.isoformat() if l.created_at else None
            }
            for l in logs
        ]
    return []

# ==================== VERIFICATION APIS ====================

@router.post("/api/v1/verify")
async def api_verify_v1(
    application_id: int = Form(...),
    api_key: str = Form(...),
    license_key: str = Form(...),
    device_id: str = Form(...),
    app_version: str = Form("1.0"),
    request: Request = None,
    db: Session = Depends(get_db)
):
    start = time.time()
    ip = get_client_ip(request) if request else "unknown"
    request_id = str(uuid.uuid4())
    
    # Check IP ban
    ip_ban = db.query(IPBan).filter(IPBan.ip_address == ip).first()
    if ip_ban and (ip_ban.is_permanent or (ip_ban.expires_at and ip_ban.expires_at > datetime.utcnow())):
        log = APIRequestLog(
            request_id=request_id,
            application_id=application_id,
            license_key=license_key,
            device_id=device_id,
            ip_address=ip,
            endpoint="/api/v1/verify",
            method="POST",
            status_code=403,
            response_time_ms=int((time.time()-start)*1000),
            is_success=False,
            error_message="IP banned"
        )
        db.add(log)
        db.commit()
        return JSONResponse(status_code=403, content={"success": False, "error": "IP banned", "request_id": request_id})
    
    result = verify_license(db, application_id, api_key, license_key, device_id)
    response_time = int((time.time()-start)*1000)
    
    log = APIRequestLog(
        request_id=result.get("request_id", request_id),
        application_id=application_id,
        license_key=license_key,
        device_id=device_id,
        ip_address=ip,
        endpoint="/api/v1/verify",
        method="POST",
        status_code=200 if result["success"] else 400,
        response_time_ms=response_time,
        is_success=result["success"],
        error_message=result.get("error")
    )
    db.add(log)
    db.commit()
    
    if result["success"]:
        data_to_sign = f"{result['license_status']}:{result['expiry_date']}:{result['server_time']}:{result['request_id']}"
        signature = sign_data(data_to_sign)
        return {
            "success": True,
            "license_status": result["license_status"].value if hasattr(result['license_status'], 'value') else str(result["license_status"]),
            "expiry_date": result["expiry_date"].isoformat() if result["expiry_date"] else None,
            "server_time": result["server_time"].isoformat(),
            "request_id": result["request_id"],
            "signature": signature
        }
    else:
        return JSONResponse(status_code=400, content={"success": False, "error": result.get("error"), "request_id": result.get("request_id", request_id)})

@router.post("/api/v2/verify")
async def api_verify_v2(
    application_id: int = Form(...),
    api_key: str = Form(...),
    license_key: str = Form(...),
    request: Request = None,
    db: Session = Depends(get_db)
):
    start = time.time()
    ip = get_client_ip(request) if request else "unknown"
    request_id = str(uuid.uuid4())
    
    # Check IP ban
    ip_ban = db.query(IPBan).filter(IPBan.ip_address == ip).first()
    if ip_ban and (ip_ban.is_permanent or (ip_ban.expires_at and ip_ban.expires_at > datetime.utcnow())):
        log = APIRequestLog(
            request_id=request_id,
            application_id=application_id,
            license_key=license_key,
            ip_address=ip,
            endpoint="/api/v2/verify",
            method="POST",
            status_code=403,
            response_time_ms=int((time.time()-start)*1000),
            is_success=False,
            error_message="IP banned"
        )
        db.add(log)
        db.commit()
        return JSONResponse(status_code=403, content={"success": False, "error": "IP banned", "request_id": request_id})
    
    result = verify_license(db, application_id, api_key, license_key, check_device=False)
    response_time = int((time.time()-start)*1000)
    
    log = APIRequestLog(
        request_id=result.get("request_id", request_id),
        application_id=application_id,
        license_key=license_key,
        ip_address=ip,
        endpoint="/api/v2/verify",
        method="POST",
        status_code=200 if result["success"] else 400,
        response_time_ms=response_time,
        is_success=result["success"],
        error_message=result.get("error")
    )
    db.add(log)
    db.commit()
    
    if result["success"]:
        data_to_sign = f"{result['license_status']}:{result['expiry_date']}:{result['server_time']}:{result['request_id']}"
        signature = sign_data(data_to_sign)
        return {
            "success": True,
            "license_status": result["license_status"].value if hasattr(result['license_status'], 'value') else str(result["license_status"]),
            "expiry_date": result["expiry_date"].isoformat() if result["expiry_date"] else None,
            "server_time": result["server_time"].isoformat(),
            "request_id": result["request_id"],
            "signature": signature
        }
    else:
        return JSONResponse(status_code=400, content={"success": False, "error": result.get("error"), "request_id": result.get("request_id", request_id)})