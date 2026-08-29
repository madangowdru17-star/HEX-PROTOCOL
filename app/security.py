import os
import hashlib
import secrets
from datetime import datetime, timedelta
from typing import Optional
from jose import JWTError, jwt
from passlib.context import CryptContext
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.backends import default_backend
from app.config import settings

pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt

def decode_access_token(token: str):
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        return payload
    except JWTError:
        return None

def hash_api_key(api_key: str) -> str:
    return hashlib.sha256(api_key.encode()).hexdigest()

def generate_api_key() -> str:
    return secrets.token_urlsafe(32)

# RSA keys for signing
_private_key = None
_public_key = None

def load_or_generate_rsa_keys():
    global _private_key, _public_key
    if _private_key is not None:
        return
    if settings.PRIVATE_KEY_PEM and settings.PUBLIC_KEY_PEM:
        _private_key = serialization.load_pem_private_key(settings.PRIVATE_KEY_PEM.encode(), password=None, backend=default_backend())
        _public_key = serialization.load_pem_public_key(settings.PUBLIC_KEY_PEM.encode(), backend=default_backend())
    elif settings.PRIVATE_KEY_PATH and settings.PUBLIC_KEY_PATH:
        with open(settings.PRIVATE_KEY_PATH, "rb") as f:
            _private_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
        with open(settings.PUBLIC_KEY_PATH, "rb") as f:
            _public_key = serialization.load_pem_public_key(f.read(), backend=default_backend())
    else:
        _private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
        _public_key = _private_key.public_key()

def sign_data(data: str) -> str:
    load_or_generate_rsa_keys()
    signature = _private_key.sign(
        data.encode(),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )
    return signature.hex()

def verify_signature(data: str, signature: str) -> bool:
    load_or_generate_rsa_keys()
    try:
        _public_key.verify(
            bytes.fromhex(signature),
            data.encode(),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False