import uuid
import re
import secrets
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from app.models import License, Application, Device, IPBan, DeviceBan
from app.security import hash_api_key

def generate_license_key() -> str:
    segments = []
    for _ in range(4):
        seg = ''.join(secrets.choice('ABCDEFGHJKLMNPQRSTUVWXYZ23456789') for _ in range(4))
        segments.append(seg)
    return '-'.join(segments)

def calculate_expiry(hours: int = None, days: int = None, expires_at: datetime = None, is_permanent: bool = False):
    if is_permanent or (hours is None and days is None and expires_at is None):
        return None
    if expires_at:
        return expires_at
    if days:
        return datetime.utcnow() + timedelta(days=days)
    if hours:
        return datetime.utcnow() + timedelta(hours=hours)
    return None

def verify_license(db: Session, application_id: int, api_key: str, license_key: str, device_id: str = None, check_device: bool = True) -> dict:
    # Verify API key
    app = db.query(Application).filter(Application.id == application_id).first()
    if not app or not app.is_active:
        return {"success": False, "error": "Application not found or inactive"}
    if hash_api_key(api_key) != app.api_key_hash:
        return {"success": False, "error": "Invalid API key"}

    # Verify license
    license_obj = db.query(License).filter(License.key == license_key, License.application_id == application_id).first()
    if not license_obj:
        return {"success": False, "error": "License key not found"}

    # Check status
    if license_obj.status == "BANNED":
        return {"success": False, "error": "License is banned"}
    if license_obj.status == "REVOKED":
        return {"success": False, "error": "License is revoked"}
    if license_obj.status == "DISABLED":
        return {"success": False, "error": "License is disabled"}

    # Check expiry
    if license_obj.expires_at is not None:
        if datetime.utcnow() > license_obj.expires_at:
            license_obj.status = "EXPIRED"
            db.commit()
            return {"success": False, "error": "License expired"}

    # Device binding
    if check_device and device_id:
        # Check if device is banned globally
        device_ban = db.query(DeviceBan).filter(DeviceBan.device_id == device_id).first()
        if device_ban and (device_ban.is_permanent or (device_ban.expires_at and device_ban.expires_at > datetime.utcnow())):
            return {"success": False, "error": "Device is banned"}

        # Check existing device
        device = db.query(Device).filter(Device.license_id == license_obj.id, Device.device_id == device_id).first()
        if device:
            if device.is_banned:
                return {"success": False, "error": "Device is banned for this license"}
            device.last_seen = datetime.utcnow()
            db.commit()
        else:
            # New device
            device_count = db.query(Device).filter(Device.license_id == license_obj.id).count()
            if license_obj.max_devices != 0 and device_count >= license_obj.max_devices:
                return {"success": False, "error": "Maximum device limit reached"}
            new_device = Device(
                device_id=device_id,
                license_id=license_obj.id,
                ip_address=None,
                is_banned=False
            )
            db.add(new_device)
            if license_obj.status == "UNUSED":
                license_obj.status = "ACTIVE"
            db.commit()

    return {
        "success": True,
        "license_status": license_obj.status,
        "expiry_date": license_obj.expires_at,
        "server_time": datetime.utcnow(),
        "request_id": str(uuid.uuid4()),
    }