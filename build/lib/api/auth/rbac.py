"""Role-Based Access Control (RBAC) Manager"""

from typing import Dict, List, Set, Optional
from enum import Enum

from ..models.user import User, UserRole


class Permission(Enum):
    """System permissions"""
    # Scan management
    SCAN_CREATE = "scan:create"
    SCAN_READ = "scan:read"
    SCAN_DELETE = "scan:delete"
    SCAN_RUN = "scan:run"
    
    # Report management
    REPORT_CREATE = "report:create"
    REPORT_READ = "report:read"
    REPORT_EXPORT = "report:export"
    REPORT_DELETE = "report:delete"
    
    # Configuration management
    CONFIG_READ = "config:read"
    CONFIG_WRITE = "config:write"
    CONFIG_POLICY_MANAGE = "config:policy:manage"
    
    # User management
    USER_CREATE = "user:create"
    USER_READ = "user:read"
    USER_UPDATE = "user:update"
    USER_DELETE = "user:delete"
    
    # API key management
    APIKEY_CREATE = "apikey:create"
    APIKEY_READ = "apikey:read"
    APIKEY_DELETE = "apikey:delete"
    
    # Webhook management
    WEBHOOK_CREATE = "webhook:create"
    WEBHOOK_READ = "webhook:read"
    WEBHOOK_UPDATE = "webhook:update"
    WEBHOOK_DELETE = "webhook:delete"
    
    # System administration
    SYSTEM_ADMIN = "system:admin"
    SYSTEM_METRICS = "system:metrics"
    SYSTEM_LOGS = "system:logs"


class RBACManager:
    """Role-Based Access Control Manager"""
    
    def __init__(self):
        self.role_permissions = self._initialize_role_permissions()
        self.resource_permissions = self._initialize_resource_permissions()
    
    def _initialize_role_permissions(self) -> Dict[UserRole, Set[Permission]]:
        """Initialize default role permissions"""
        return {
            UserRole.ADMIN: {
                # Full system access
                Permission.SCAN_CREATE, Permission.SCAN_READ, Permission.SCAN_DELETE, Permission.SCAN_RUN,
                Permission.REPORT_CREATE, Permission.REPORT_READ, Permission.REPORT_EXPORT, Permission.REPORT_DELETE,
                Permission.CONFIG_READ, Permission.CONFIG_WRITE, Permission.CONFIG_POLICY_MANAGE,
                Permission.USER_CREATE, Permission.USER_READ, Permission.USER_UPDATE, Permission.USER_DELETE,
                Permission.APIKEY_CREATE, Permission.APIKEY_READ, Permission.APIKEY_DELETE,
                Permission.WEBHOOK_CREATE, Permission.WEBHOOK_READ, Permission.WEBHOOK_UPDATE, Permission.WEBHOOK_DELETE,
                Permission.SYSTEM_ADMIN, Permission.SYSTEM_METRICS, Permission.SYSTEM_LOGS
            },
            
            UserRole.DEVELOPER: {
                # Developer workflow access
                Permission.SCAN_CREATE, Permission.SCAN_READ, Permission.SCAN_RUN,
                Permission.REPORT_CREATE, Permission.REPORT_READ, Permission.REPORT_EXPORT,
                Permission.CONFIG_READ,
                Permission.APIKEY_CREATE, Permission.APIKEY_READ,
                Permission.WEBHOOK_CREATE, Permission.WEBHOOK_READ, Permission.WEBHOOK_UPDATE,
                Permission.SYSTEM_METRICS
            },
            
            UserRole.VIEWER: {
                # Read-only access
                Permission.SCAN_READ,
                Permission.REPORT_READ,
                Permission.CONFIG_READ,
                Permission.WEBHOOK_READ
            }
        }
    
    def _initialize_resource_permissions(self) -> Dict[str, List[Permission]]:
        """Initialize resource-based permission requirements"""
        return {
            # Scan endpoints
            "POST:/api/v1/scans": [Permission.SCAN_CREATE],
            "GET:/api/v1/scans": [Permission.SCAN_READ],
            "GET:/api/v1/scans/{scan_id}": [Permission.SCAN_READ],
            "DELETE:/api/v1/scans/{scan_id}": [Permission.SCAN_DELETE],
            "POST:/api/v1/scans/{scan_id}/run": [Permission.SCAN_RUN],
            
            # Report endpoints
            "GET:/api/v1/reports/{scan_id}": [Permission.REPORT_READ],
            "POST:/api/v1/reports/export": [Permission.REPORT_EXPORT],
            "DELETE:/api/v1/reports/{report_id}": [Permission.REPORT_DELETE],
            
            # Configuration endpoints
            "GET:/api/v1/config": [Permission.CONFIG_READ],
            "PUT:/api/v1/config": [Permission.CONFIG_WRITE],
            "GET:/api/v1/config/policies": [Permission.CONFIG_READ],
            "PUT:/api/v1/config/policies": [Permission.CONFIG_POLICY_MANAGE],
            
            # User management endpoints
            "POST:/api/v1/users": [Permission.USER_CREATE],
            "GET:/api/v1/users": [Permission.USER_READ],
            "PUT:/api/v1/users/{user_id}": [Permission.USER_UPDATE],
            "DELETE:/api/v1/users/{user_id}": [Permission.USER_DELETE],
            
            # API key endpoints
            "POST:/api/v1/auth/api-keys": [Permission.APIKEY_CREATE],
            "GET:/api/v1/auth/api-keys": [Permission.APIKEY_READ],
            "DELETE:/api/v1/auth/api-keys/{key_id}": [Permission.APIKEY_DELETE],
            
            # Webhook endpoints
            "POST:/api/v1/webhooks": [Permission.WEBHOOK_CREATE],
            "GET:/api/v1/webhooks": [Permission.WEBHOOK_READ],
            "PUT:/api/v1/webhooks/{webhook_id}": [Permission.WEBHOOK_UPDATE],
            "DELETE:/api/v1/webhooks/{webhook_id}": [Permission.WEBHOOK_DELETE],
            
            # System endpoints
            "GET:/api/v1/system/metrics": [Permission.SYSTEM_METRICS],
            "GET:/api/v1/system/logs": [Permission.SYSTEM_LOGS],
            "POST:/api/v1/system/admin": [Permission.SYSTEM_ADMIN]
        }
    
    def has_permission(self, user_role: UserRole, permission: Permission) -> bool:
        """Check if role has specific permission"""
        return permission in self.role_permissions.get(user_role, set())
    
    def has_permissions(self, user_role: UserRole, permissions: List[Permission]) -> bool:
        """Check if role has all specified permissions"""
        role_perms = self.role_permissions.get(user_role, set())
        return all(perm in role_perms for perm in permissions)
    
    def can_access_resource(self, user_role: UserRole, method: str, path: str) -> bool:
        """Check if role can access specific resource"""
        resource_key = f"{method}:{path}"
        required_permissions = self.resource_permissions.get(resource_key, [])
        
        if not required_permissions:
            # No specific permissions required
            return True
        
        return self.has_permissions(user_role, required_permissions)
    
    def get_user_permissions(self, user_role: UserRole) -> List[str]:
        """Get all permissions for a user role"""
        permissions = self.role_permissions.get(user_role, set())
        return [perm.value for perm in permissions]
    
    def can_user_access_resource(self, user: User, method: str, path: str) -> bool:
        """Check if specific user can access resource"""
        return self.can_access_resource(user.role, method, path)
    
    def filter_accessible_resources(self, user_role: UserRole, resources: List[str]) -> List[str]:
        """Filter resources that the role can access"""
        accessible = []
        for resource in resources:
            if ':' in resource:
                method, path = resource.split(':', 1)
                if self.can_access_resource(user_role, method, path):
                    accessible.append(resource)
        return accessible
    
    def add_role_permission(self, role: UserRole, permission: Permission) -> None:
        """Add permission to role"""
        if role not in self.role_permissions:
            self.role_permissions[role] = set()
        self.role_permissions[role].add(permission)
    
    def remove_role_permission(self, role: UserRole, permission: Permission) -> None:
        """Remove permission from role"""
        if role in self.role_permissions:
            self.role_permissions[role].discard(permission)
    
    def add_resource_permission(self, resource: str, permission: Permission) -> None:
        """Add permission requirement to resource"""
        if resource not in self.resource_permissions:
            self.resource_permissions[resource] = []
        if permission not in self.resource_permissions[resource]:
            self.resource_permissions[resource].append(permission)
    
    def get_role_capabilities(self, role: UserRole) -> Dict[str, List[str]]:
        """Get detailed capabilities for a role"""
        permissions = self.role_permissions.get(role, set())
        
        capabilities = {
            "scans": [],
            "reports": [],
            "config": [],
            "users": [],
            "api_keys": [],
            "webhooks": [],
            "system": []
        }
        
        for perm in permissions:
            perm_str = perm.value
            if perm_str.startswith("scan:"):
                capabilities["scans"].append(perm_str.split(":", 1)[1])
            elif perm_str.startswith("report:"):
                capabilities["reports"].append(perm_str.split(":", 1)[1])
            elif perm_str.startswith("config:"):
                capabilities["config"].append(perm_str.split(":", 1)[1])
            elif perm_str.startswith("user:"):
                capabilities["users"].append(perm_str.split(":", 1)[1])
            elif perm_str.startswith("apikey:"):
                capabilities["api_keys"].append(perm_str.split(":", 1)[1])
            elif perm_str.startswith("webhook:"):
                capabilities["webhooks"].append(perm_str.split(":", 1)[1])
            elif perm_str.startswith("system:"):
                capabilities["system"].append(perm_str.split(":", 1)[1])
        
        return capabilities
    
    def check_resource_access(self, user_permissions: List[str], method: str, path: str) -> bool:
        """Check resource access using permission list"""
        resource_key = f"{method}:{path}"
        required_permissions = self.resource_permissions.get(resource_key, [])
        
        if not required_permissions:
            return True
        
        required_perm_values = [perm.value for perm in required_permissions]
        return all(perm in user_permissions for perm in required_perm_values)