"""API Key Authentication"""

import hashlib
import secrets
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from collections import defaultdict
import time

from ..models.user import APIKey, User, UserRole


class RateLimiter:
    """Simple in-memory rate limiter"""
    
    def __init__(self):
        self.requests = defaultdict(list)
        self.cleanup_interval = 3600  # cleanup every hour
        self.last_cleanup = time.time()
    
    def is_allowed(self, key: str, limit: int, window: int = 3600) -> bool:
        """Check if request is within rate limit"""
        now = time.time()
        
        # Cleanup old entries periodically
        if now - self.last_cleanup > self.cleanup_interval:
            self._cleanup(now)
        
        # Get recent requests for this key
        key_requests = self.requests[key]
        cutoff = now - window
        
        # Remove old requests
        key_requests[:] = [req_time for req_time in key_requests if req_time > cutoff]
        
        # Check if under limit
        if len(key_requests) >= limit:
            return False
        
        # Add current request
        key_requests.append(now)
        return True
    
    def _cleanup(self, now: float):
        """Clean up old entries"""
        cutoff = now - 7200  # 2 hours
        for key in list(self.requests.keys()):
            self.requests[key] = [
                req_time for req_time in self.requests[key] 
                if req_time > cutoff
            ]
            if not self.requests[key]:
                del self.requests[key]
        self.last_cleanup = now


class APIKeyAuth:
    """API Key Authentication and Management"""
    
    def __init__(self):
        self.api_keys: Dict[str, APIKey] = {}
        self.key_to_user: Dict[str, str] = {}  # key_hash -> user_id
        self.rate_limiter = RateLimiter()
    
    def generate_api_key(self, name: str, user_id: str, permissions: List[str], 
                        expires_days: Optional[int] = None) -> Tuple[APIKey, str]:
        """Generate new API key"""
        api_key, raw_key = APIKey.generate_key(name, user_id, permissions, expires_days)
        
        # Store the API key
        self.api_keys[api_key.id] = api_key
        self.key_to_user[api_key.key_hash] = user_id
        
        return api_key, raw_key
    
    def verify_api_key(self, raw_key: str) -> Optional[APIKey]:
        """Verify API key and return key object if valid"""
        if not raw_key.startswith('vg_'):
            return None
        
        try:
            # Parse key format: vg_{key_id}_{key_data}
            parts = raw_key.split('_', 2)
            if len(parts) != 3:
                return None
            
            key_id = parts[1]
            key_data = parts[2]
            
            # Find API key
            api_key = self.api_keys.get(key_id)
            if not api_key:
                return None
            
            # Verify key data
            if not api_key.verify_key(key_data):
                return None
            
            # Check if key is valid
            if not api_key.is_valid():
                return None
            
            # Update last used timestamp
            api_key.last_used = datetime.utcnow()
            
            return api_key
            
        except Exception:
            return None
    
    def check_rate_limit(self, api_key: APIKey) -> bool:
        """Check if API key is within rate limits"""
        return self.rate_limiter.is_allowed(
            api_key.id, 
            api_key.rate_limit, 
            3600  # 1 hour window
        )
    
    def revoke_api_key(self, key_id: str) -> bool:
        """Revoke API key"""
        api_key = self.api_keys.get(key_id)
        if not api_key:
            return False
        
        api_key.is_active = False
        
        # Remove from key lookup
        if api_key.key_hash in self.key_to_user:
            del self.key_to_user[api_key.key_hash]
        
        return True
    
    def list_user_keys(self, user_id: str) -> List[APIKey]:
        """List all API keys for a user"""
        return [key for key in self.api_keys.values() if key.user_id == user_id]
    
    def get_key_stats(self, key_id: str) -> Optional[Dict[str, any]]:
        """Get API key usage statistics"""
        api_key = self.api_keys.get(key_id)
        if not api_key:
            return None
        
        return {
            "id": api_key.id,
            "name": api_key.name,
            "created_at": api_key.created_at.isoformat(),
            "last_used": api_key.last_used.isoformat() if api_key.last_used else None,
            "expires_at": api_key.expires_at.isoformat() if api_key.expires_at else None,
            "is_active": api_key.is_active,
            "permissions": api_key.permissions,
            "rate_limit": api_key.rate_limit,
            "is_expired": api_key.expires_at and api_key.expires_at < datetime.utcnow()
        }
    
    def cleanup_expired_keys(self) -> int:
        """Clean up expired API keys"""
        expired_count = 0
        now = datetime.utcnow()
        
        for key_id in list(self.api_keys.keys()):
            api_key = self.api_keys[key_id]
            if api_key.expires_at and api_key.expires_at < now:
                api_key.is_active = False
                expired_count += 1
        
        return expired_count
    
    def update_key_permissions(self, key_id: str, permissions: List[str]) -> bool:
        """Update API key permissions"""
        api_key = self.api_keys.get(key_id)
        if not api_key:
            return False
        
        api_key.permissions = permissions
        return True
    
    def update_rate_limit(self, key_id: str, rate_limit: int) -> bool:
        """Update API key rate limit"""
        api_key = self.api_keys.get(key_id)
        if not api_key:
            return False
        
        api_key.rate_limit = rate_limit
        return True
    
    def authenticate_request(self, raw_key: str) -> Optional[Dict[str, any]]:
        """Authenticate API request and return user context"""
        api_key = self.verify_api_key(raw_key)
        if not api_key:
            return None
        
        # Check rate limits
        if not self.check_rate_limit(api_key):
            return {
                "error": "rate_limit_exceeded",
                "message": f"Rate limit of {api_key.rate_limit} requests/hour exceeded"
            }
        
        return {
            "api_key_id": api_key.id,
            "user_id": api_key.user_id,
            "permissions": api_key.permissions,
            "rate_limit": api_key.rate_limit,
            "authenticated": True
        }