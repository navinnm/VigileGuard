"""JWT Token Management"""

import json
import secrets
from datetime import datetime, timedelta
from typing import Dict, Optional, Any
import hashlib
import hmac
import base64


class JWTHandler:
    """Lightweight JWT token handler without external dependencies"""
    
    def __init__(self, secret_key: Optional[str] = None, algorithm: str = "HS256"):
        self.secret_key = secret_key or secrets.token_urlsafe(32)
        self.algorithm = algorithm
        self.default_expiry = timedelta(hours=24)
    
    def _base64_url_encode(self, data: bytes) -> str:
        """Base64 URL-safe encode"""
        return base64.urlsafe_b64encode(data).decode('utf-8').rstrip('=')
    
    def _base64_url_decode(self, data: str) -> bytes:
        """Base64 URL-safe decode"""
        # Add padding if needed
        padding = 4 - len(data) % 4
        if padding != 4:
            data += '=' * padding
        return base64.urlsafe_b64decode(data)
    
    def _sign(self, message: str) -> str:
        """Create HMAC signature"""
        signature = hmac.new(
            self.secret_key.encode('utf-8'),
            message.encode('utf-8'),
            hashlib.sha256
        ).digest()
        return self._base64_url_encode(signature)
    
    def create_token(self, payload: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
        """Create JWT token"""
        # Header
        header = {
            "alg": self.algorithm,
            "typ": "JWT"
        }
        
        # Payload with standard claims
        now = datetime.utcnow()
        exp_delta = expires_delta or self.default_expiry
        
        token_payload = {
            "iat": int(now.timestamp()),
            "exp": int((now + exp_delta).timestamp()),
            "jti": secrets.token_urlsafe(16),  # unique token ID
            **payload
        }
        
        # Encode header and payload
        encoded_header = self._base64_url_encode(json.dumps(header, separators=(',', ':')).encode())
        encoded_payload = self._base64_url_encode(json.dumps(token_payload, separators=(',', ':')).encode())
        
        # Create signature
        message = f"{encoded_header}.{encoded_payload}"
        signature = self._sign(message)
        
        return f"{message}.{signature}"
    
    def verify_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Verify and decode JWT token"""
        try:
            parts = token.split('.')
            if len(parts) != 3:
                return None
            
            header_encoded, payload_encoded, signature_encoded = parts
            
            # Verify signature
            message = f"{header_encoded}.{payload_encoded}"
            expected_signature = self._sign(message)
            
            if not hmac.compare_digest(signature_encoded, expected_signature):
                return None
            
            # Decode payload
            payload_json = self._base64_url_decode(payload_encoded).decode('utf-8')
            payload = json.loads(payload_json)
            
            # Check expiration
            if 'exp' in payload:
                exp_timestamp = payload['exp']
                if datetime.utcnow().timestamp() > exp_timestamp:
                    return None
            
            return payload
            
        except Exception:
            return None
    
    def refresh_token(self, token: str) -> Optional[str]:
        """Refresh a valid token with new expiration"""
        payload = self.verify_token(token)
        if not payload:
            return None
        
        # Remove timestamp claims for refresh
        refresh_payload = {k: v for k, v in payload.items() 
                          if k not in ['iat', 'exp', 'jti']}
        
        return self.create_token(refresh_payload)
    
    def decode_token_unsafe(self, token: str) -> Optional[Dict[str, Any]]:
        """Decode token without verification (for debugging)"""
        try:
            parts = token.split('.')
            if len(parts) != 3:
                return None
            
            payload_encoded = parts[1]
            payload_json = self._base64_url_decode(payload_encoded).decode('utf-8')
            return json.loads(payload_json)
            
        except Exception:
            return None
    
    def create_access_token(self, user_id: str, username: str, role: str, 
                           permissions: list) -> str:
        """Create access token with user information"""
        payload = {
            "sub": user_id,  # subject (user ID)
            "username": username,
            "role": role,
            "permissions": permissions,
            "type": "access"
        }
        return self.create_token(payload)
    
    def create_refresh_token(self, user_id: str) -> str:
        """Create refresh token"""
        payload = {
            "sub": user_id,
            "type": "refresh"
        }
        return self.create_token(payload, expires_delta=timedelta(days=30))
    
    def extract_user_info(self, token: str) -> Optional[Dict[str, Any]]:
        """Extract user information from valid token"""
        payload = self.verify_token(token)
        if not payload:
            return None
        
        return {
            "user_id": payload.get("sub"),
            "username": payload.get("username"),
            "role": payload.get("role"),
            "permissions": payload.get("permissions", []),
            "token_type": payload.get("type", "access")
        }