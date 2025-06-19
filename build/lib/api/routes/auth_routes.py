"""Authentication API Routes"""

from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from fastapi import APIRouter, HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field

from ..auth.jwt_handler import JWTHandler
from ..auth.api_key_auth import APIKeyAuth
from ..auth.rbac import RBACManager
from ..models.user import User, UserRole, APIKey


# Pydantic models for API requests/responses
class LoginRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=6)


class LoginResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int = 86400  # 24 hours
    user_info: Dict[str, Any]


class RefreshRequest(BaseModel):
    refresh_token: str


class APIKeyCreateRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    permissions: List[str] = Field(default_factory=list)
    expires_days: Optional[int] = Field(None, ge=1, le=365)


class APIKeyResponse(BaseModel):
    id: str
    name: str
    key: Optional[str] = None  # Only included on creation
    permissions: List[str]
    created_at: str
    expires_at: Optional[str] = None
    last_used: Optional[str] = None
    is_active: bool


# Initialize authentication components
auth_router = APIRouter(prefix="/auth", tags=["authentication"])
jwt_handler = JWTHandler()
api_key_auth = APIKeyAuth()
rbac_manager = RBACManager()
security = HTTPBearer()

# In-memory user store (replace with database in production)
users_db = {
    "admin": User(
        id="user_001",
        username="admin",
        email="admin@vigileguard.local",
        role=UserRole.ADMIN,
        created_at=datetime.utcnow(),
        password_hash="$2b$12$dummy_hash_for_demo"  # Use proper password hashing
    )
}


def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> User:
    """Extract current user from JWT token"""
    token = credentials.credentials
    user_info = jwt_handler.extract_user_info(token)
    
    if not user_info:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token"
        )
    
    # Find user in database
    user = None
    for u in users_db.values():
        if u.id == user_info["user_id"]:
            user = u
            break
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found"
        )
    
    return user


def get_api_key_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> Dict[str, Any]:
    """Extract user info from API key"""
    raw_key = credentials.credentials
    
    if not raw_key.startswith('vg_'):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key format"
        )
    
    auth_result = api_key_auth.authenticate_request(raw_key)
    
    if not auth_result or not auth_result.get("authenticated"):
        error_msg = auth_result.get("message", "Invalid API key") if auth_result else "Invalid API key"
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=error_msg
        )
    
    return auth_result


def verify_permission(permission: str):
    """Dependency to verify user has specific permission"""
    def permission_checker(user: User = Depends(get_current_user)) -> User:
        if not rbac_manager.has_permission(user.role, permission):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission denied: {permission}"
            )
        return user
    return permission_checker


@auth_router.post("/login", response_model=LoginResponse)
async def login(login_data: LoginRequest):
    """Authenticate user and return JWT tokens"""
    
    # Find user (simple lookup for demo - use proper authentication in production)
    user = users_db.get(login_data.username)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password"
        )
    
    # Verify password (simplified for demo)
    if login_data.password != "admin123":  # Use proper password verification
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password"
        )
    
    # Update last login
    user.last_login = datetime.utcnow()
    
    # Create tokens
    permissions = rbac_manager.get_user_permissions(user.role)
    access_token = jwt_handler.create_access_token(
        user.id, user.username, user.role.value, permissions
    )
    refresh_token = jwt_handler.create_refresh_token(user.id)
    
    return LoginResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        user_info={
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "role": user.role.value,
            "permissions": permissions
        }
    )


@auth_router.post("/refresh", response_model=LoginResponse)
async def refresh_token(refresh_data: RefreshRequest):
    """Refresh access token using refresh token"""
    
    user_info = jwt_handler.extract_user_info(refresh_data.refresh_token)
    if not user_info or user_info.get("token_type") != "refresh":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token"
        )
    
    # Find user
    user = None
    for u in users_db.values():
        if u.id == user_info["user_id"]:
            user = u
            break
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found"
        )
    
    # Create new tokens
    permissions = rbac_manager.get_user_permissions(user.role)
    access_token = jwt_handler.create_access_token(
        user.id, user.username, user.role.value, permissions
    )
    new_refresh_token = jwt_handler.create_refresh_token(user.id)
    
    return LoginResponse(
        access_token=access_token,
        refresh_token=new_refresh_token,
        user_info={
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "role": user.role.value,
            "permissions": permissions
        }
    )


@auth_router.post("/api-keys", response_model=APIKeyResponse)
async def create_api_key(
    key_data: APIKeyCreateRequest,
    current_user: User = Depends(get_current_user)
):
    """Create new API key"""
    
    # Verify user can create API keys
    if not rbac_manager.has_permission(current_user.role, "apikey:create"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Permission denied: cannot create API keys"
        )
    
    # Generate API key
    api_key, raw_key = api_key_auth.generate_api_key(
        key_data.name,
        current_user.id,
        key_data.permissions,
        key_data.expires_days
    )
    
    return APIKeyResponse(
        id=api_key.id,
        name=api_key.name,
        key=raw_key,  # Only returned on creation
        permissions=api_key.permissions,
        created_at=api_key.created_at.isoformat(),
        expires_at=api_key.expires_at.isoformat() if api_key.expires_at else None,
        is_active=api_key.is_active
    )


@auth_router.get("/api-keys", response_model=List[APIKeyResponse])
async def list_api_keys(current_user: User = Depends(get_current_user)):
    """List user's API keys"""
    
    if not rbac_manager.has_permission(current_user.role, "apikey:read"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Permission denied: cannot read API keys"
        )
    
    api_keys = api_key_auth.list_user_keys(current_user.id)
    
    return [
        APIKeyResponse(
            id=key.id,
            name=key.name,
            permissions=key.permissions,
            created_at=key.created_at.isoformat(),
            expires_at=key.expires_at.isoformat() if key.expires_at else None,
            last_used=key.last_used.isoformat() if key.last_used else None,
            is_active=key.is_active
        )
        for key in api_keys
    ]


@auth_router.delete("/api-keys/{key_id}")
async def revoke_api_key(
    key_id: str,
    current_user: User = Depends(get_current_user)
):
    """Revoke API key"""
    
    if not rbac_manager.has_permission(current_user.role, "apikey:delete"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Permission denied: cannot delete API keys"
        )
    
    # Check if key belongs to user (or user is admin)
    api_keys = api_key_auth.list_user_keys(current_user.id)
    key_exists = any(key.id == key_id for key in api_keys)
    
    if not key_exists and current_user.role != UserRole.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="API key not found"
        )
    
    success = api_key_auth.revoke_api_key(key_id)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="API key not found"
        )
    
    return {"message": "API key revoked successfully"}


@auth_router.get("/me")
async def get_current_user_info(current_user: User = Depends(get_current_user)):
    """Get current user information"""
    
    permissions = rbac_manager.get_user_permissions(current_user.role)
    capabilities = rbac_manager.get_role_capabilities(current_user.role)
    
    return {
        "id": current_user.id,
        "username": current_user.username,
        "email": current_user.email,
        "role": current_user.role.value,
        "permissions": permissions,
        "capabilities": capabilities,
        "created_at": current_user.created_at.isoformat(),
        "last_login": current_user.last_login.isoformat() if current_user.last_login else None,
        "is_active": current_user.is_active
    }


@auth_router.post("/verify")
async def verify_token(current_user: User = Depends(get_current_user)):
    """Verify token validity"""
    return {
        "valid": True,
        "user_id": current_user.id,
        "username": current_user.username,
        "role": current_user.role.value
    }