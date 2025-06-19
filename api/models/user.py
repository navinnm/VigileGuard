"""User and Authentication Models"""

from datetime import datetime, timedelta
from enum import Enum
from typing import Optional, List
from dataclasses import dataclass, field
import secrets
import hashlib


class UserRole(Enum):
    """User role enumeration for RBAC"""
    ADMIN = "admin"
    DEVELOPER = "developer"
    VIEWER = "viewer"


@dataclass
class User:
    """User model for authentication and authorization"""
    id: str
    username: str
    email: str
    role: UserRole
    created_at: datetime
    last_login: Optional[datetime] = None
    is_active: bool = True
    password_hash: Optional[str] = None
    
    def has_permission(self, permission: str) -> bool:
        """Check if user has specific permission based on role"""
        permissions = {
            UserRole.ADMIN: {"read", "write", "delete", "manage_users", "manage_config"},
            UserRole.DEVELOPER: {"read", "write", "run_scans", "export_reports"},
            UserRole.VIEWER: {"read", "view_reports"}
        }
        return permission in permissions.get(self.role, set())


@dataclass
class APIKey:
    """API Key model for programmatic access"""
    id: str
    name: str
    key_hash: str
    user_id: str
    permissions: List[str]
    created_at: datetime
    expires_at: Optional[datetime] = None
    last_used: Optional[datetime] = None
    is_active: bool = True
    rate_limit: int = 1000  # requests per hour
    
    @classmethod
    def generate_key(cls, name: str, user_id: str, permissions: List[str], 
                    expires_days: Optional[int] = None) -> tuple['APIKey', str]:
        """Generate new API key with secure random token"""
        key_id = secrets.token_urlsafe(16)
        raw_key = secrets.token_urlsafe(32)
        key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
        
        expires_at = None
        if expires_days:
            expires_at = datetime.utcnow() + timedelta(days=expires_days)
        
        api_key = cls(
            id=key_id,
            name=name,
            key_hash=key_hash,
            user_id=user_id,
            permissions=permissions,
            created_at=datetime.utcnow(),
            expires_at=expires_at
        )
        
        return api_key, f"vg_{key_id}_{raw_key}"
    
    def is_valid(self) -> bool:
        """Check if API key is valid and not expired"""
        if not self.is_active:
            return False
        if self.expires_at and self.expires_at < datetime.utcnow():
            return False
        return True
    
    def verify_key(self, raw_key: str) -> bool:
        """Verify raw key against stored hash"""
        provided_hash = hashlib.sha256(raw_key.encode()).hexdigest()
        return provided_hash == self.key_hash