"""Configuration Management API Routes"""

from typing import Dict, List, Optional, Any
from fastapi import APIRouter, HTTPException, Depends, status
from pydantic import BaseModel, Field

from ..auth.rbac import RBACManager, Permission
from ..models.user import User
from .auth_routes import get_current_user


# Pydantic models for API requests/responses
class ConfigResponse(BaseModel):
    checkers: Dict[str, Any]
    severity_thresholds: Dict[str, int]
    notifications: Dict[str, Any]
    api_settings: Dict[str, Any]
    system_settings: Dict[str, Any]


class ConfigUpdateRequest(BaseModel):
    checkers: Optional[Dict[str, Any]] = None
    severity_thresholds: Optional[Dict[str, int]] = None
    notifications: Optional[Dict[str, Any]] = None
    api_settings: Optional[Dict[str, Any]] = None
    system_settings: Optional[Dict[str, Any]] = None


class PolicyResponse(BaseModel):
    id: str
    name: str
    description: str
    rules: Dict[str, Any]
    enabled: bool
    created_at: str
    updated_at: str


class PolicyCreateRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    description: str = Field("", max_length=500)
    rules: Dict[str, Any] = Field(default_factory=dict)
    enabled: bool = True


# Initialize components
config_router = APIRouter(prefix="/config", tags=["configuration"])
rbac_manager = RBACManager()

# Mock configuration storage (replace with database in production)
system_config = {
    "checkers": {
        "ssh": {
            "enabled": True,
            "check_key_auth": True,
            "check_root_login": False,
            "allowed_users": [],
            "timeout": 30
        },
        "firewall": {
            "enabled": True,
            "required_rules": ["ssh", "http", "https"],
            "allowed_ports": [22, 80, 443],
            "check_status": True
        },
        "web_server": {
            "enabled": True,
            "check_ssl": True,
            "check_headers": True,
            "required_headers": ["X-Frame-Options", "X-Content-Type-Options"],
            "ssl_min_version": "TLSv1.2"
        },
        "file_permissions": {
            "enabled": True,
            "check_world_writable": True,
            "check_suid_files": True,
            "excluded_paths": ["/tmp", "/var/tmp"]
        }
    },
    "severity_thresholds": {
        "critical": 0,
        "high": 3,
        "medium": 10,
        "low": 20
    },
    "notifications": {
        "email": {
            "enabled": False,
            "smtp_server": "",
            "smtp_port": 587,
            "username": "",
            "recipients": []
        },
        "slack": {
            "enabled": False,
            "webhook_url": "",
            "channel": "#security",
            "username": "VigileGuard"
        },
        "webhooks": {
            "enabled": True,
            "max_retries": 3,
            "timeout": 30
        }
    },
    "api_settings": {
        "rate_limiting": {
            "enabled": True,
            "requests_per_hour": 1000,
            "burst_limit": 10
        },
        "authentication": {
            "jwt_expiry_hours": 24,
            "refresh_token_days": 30,
            "api_key_expiry_days": 365
        },
        "cors": {
            "enabled": True,
            "allowed_origins": ["http://localhost:3000"],
            "allowed_methods": ["GET", "POST", "PUT", "DELETE"]
        }
    },
    "system_settings": {
        "scan_timeout": 300,
        "max_concurrent_scans": 5,
        "report_retention_days": 90,
        "log_level": "INFO",
        "enable_metrics": True
    }
}

policies = {}


def require_config_permission(permission: Permission):
    """Dependency to check configuration permissions"""
    def permission_checker(current_user: User = Depends(get_current_user)) -> User:
        if not rbac_manager.has_permission(current_user.role, permission):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission denied: {permission.value}"
            )
        return current_user
    return permission_checker


@config_router.get("/", response_model=ConfigResponse)
async def get_configuration(
    current_user: User = Depends(require_config_permission(Permission.CONFIG_READ))
):
    """Get system configuration"""
    
    return ConfigResponse(
        checkers=system_config["checkers"],
        severity_thresholds=system_config["severity_thresholds"],
        notifications=system_config["notifications"],
        api_settings=system_config["api_settings"],
        system_settings=system_config["system_settings"]
    )


@config_router.put("/", response_model=ConfigResponse)
async def update_configuration(
    config_data: ConfigUpdateRequest,
    current_user: User = Depends(require_config_permission(Permission.CONFIG_WRITE))
):
    """Update system configuration"""
    
    # Update configuration sections
    if config_data.checkers is not None:
        system_config["checkers"].update(config_data.checkers)
    
    if config_data.severity_thresholds is not None:
        system_config["severity_thresholds"].update(config_data.severity_thresholds)
    
    if config_data.notifications is not None:
        system_config["notifications"].update(config_data.notifications)
    
    if config_data.api_settings is not None:
        system_config["api_settings"].update(config_data.api_settings)
    
    if config_data.system_settings is not None:
        system_config["system_settings"].update(config_data.system_settings)
    
    return ConfigResponse(
        checkers=system_config["checkers"],
        severity_thresholds=system_config["severity_thresholds"],
        notifications=system_config["notifications"],
        api_settings=system_config["api_settings"],
        system_settings=system_config["system_settings"]
    )


@config_router.get("/checkers")
async def get_checker_config(
    current_user: User = Depends(require_config_permission(Permission.CONFIG_READ))
):
    """Get security checker configuration"""
    
    return {
        "checkers": system_config["checkers"],
        "available_checkers": [
            {
                "name": "ssh",
                "description": "SSH configuration and security checks",
                "options": ["check_key_auth", "check_root_login", "allowed_users"]
            },
            {
                "name": "firewall",
                "description": "Firewall rules and status verification",
                "options": ["required_rules", "allowed_ports", "check_status"]
            },
            {
                "name": "web_server",
                "description": "Web server security configuration",
                "options": ["check_ssl", "check_headers", "ssl_min_version"]
            },
            {
                "name": "file_permissions",
                "description": "File and directory permission checks",
                "options": ["check_world_writable", "check_suid_files", "excluded_paths"]
            }
        ]
    }


@config_router.put("/checkers")
async def update_checker_config(
    checker_config: Dict[str, Any],
    current_user: User = Depends(require_config_permission(Permission.CONFIG_WRITE))
):
    """Update security checker configuration"""
    
    system_config["checkers"].update(checker_config)
    
    return {
        "message": "Checker configuration updated successfully",
        "checkers": system_config["checkers"]
    }


@config_router.get("/policies", response_model=List[PolicyResponse])
async def list_policies(
    current_user: User = Depends(require_config_permission(Permission.CONFIG_READ))
):
    """List security policies"""
    
    return [
        PolicyResponse(
            id=policy_id,
            name=policy["name"],
            description=policy["description"],
            rules=policy["rules"],
            enabled=policy["enabled"],
            created_at=policy["created_at"],
            updated_at=policy["updated_at"]
        )
        for policy_id, policy in policies.items()
    ]


@config_router.post("/policies", response_model=PolicyResponse)
async def create_policy(
    policy_data: PolicyCreateRequest,
    current_user: User = Depends(require_config_permission(Permission.CONFIG_POLICY_MANAGE))
):
    """Create security policy"""
    
    from datetime import datetime
    import uuid
    
    policy_id = f"policy_{uuid.uuid4().hex[:8]}"
    policy = {
        "name": policy_data.name,
        "description": policy_data.description,
        "rules": policy_data.rules,
        "enabled": policy_data.enabled,
        "created_at": datetime.utcnow().isoformat(),
        "updated_at": datetime.utcnow().isoformat(),
        "created_by": current_user.id
    }
    
    policies[policy_id] = policy
    
    return PolicyResponse(
        id=policy_id,
        name=policy["name"],
        description=policy["description"],
        rules=policy["rules"],
        enabled=policy["enabled"],
        created_at=policy["created_at"],
        updated_at=policy["updated_at"]
    )


@config_router.get("/policies/{policy_id}", response_model=PolicyResponse)
async def get_policy(
    policy_id: str,
    current_user: User = Depends(require_config_permission(Permission.CONFIG_READ))
):
    """Get security policy details"""
    
    policy = policies.get(policy_id)
    if not policy:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Policy not found"
        )
    
    return PolicyResponse(
        id=policy_id,
        name=policy["name"],
        description=policy["description"],
        rules=policy["rules"],
        enabled=policy["enabled"],
        created_at=policy["created_at"],
        updated_at=policy["updated_at"]
    )


@config_router.put("/policies/{policy_id}", response_model=PolicyResponse)
async def update_policy(
    policy_id: str,
    policy_data: PolicyCreateRequest,
    current_user: User = Depends(require_config_permission(Permission.CONFIG_POLICY_MANAGE))
):
    """Update security policy"""
    
    policy = policies.get(policy_id)
    if not policy:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Policy not found"
        )
    
    from datetime import datetime
    
    # Update policy
    policy["name"] = policy_data.name
    policy["description"] = policy_data.description
    policy["rules"] = policy_data.rules
    policy["enabled"] = policy_data.enabled
    policy["updated_at"] = datetime.utcnow().isoformat()
    
    return PolicyResponse(
        id=policy_id,
        name=policy["name"],
        description=policy["description"],
        rules=policy["rules"],
        enabled=policy["enabled"],
        created_at=policy["created_at"],
        updated_at=policy["updated_at"]
    )


@config_router.delete("/policies/{policy_id}")
async def delete_policy(
    policy_id: str,
    current_user: User = Depends(require_config_permission(Permission.CONFIG_POLICY_MANAGE))
):
    """Delete security policy"""
    
    if policy_id not in policies:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Policy not found"
        )
    
    del policies[policy_id]
    
    return {"message": "Policy deleted successfully"}


@config_router.post("/validate")
async def validate_configuration(
    config_data: ConfigUpdateRequest,
    current_user: User = Depends(require_config_permission(Permission.CONFIG_READ))
):
    """Validate configuration without applying changes"""
    
    validation_results = {
        "valid": True,
        "warnings": [],
        "errors": []
    }
    
    # Validate checkers
    if config_data.checkers:
        for checker_name, checker_config in config_data.checkers.items():
            if checker_name not in ["ssh", "firewall", "web_server", "file_permissions"]:
                validation_results["warnings"].append(f"Unknown checker: {checker_name}")
            
            if not isinstance(checker_config, dict):
                validation_results["errors"].append(f"Invalid configuration for checker: {checker_name}")
                validation_results["valid"] = False
    
    # Validate severity thresholds
    if config_data.severity_thresholds:
        required_severities = ["critical", "high", "medium", "low"]
        for severity in required_severities:
            if severity not in config_data.severity_thresholds:
                validation_results["warnings"].append(f"Missing severity threshold: {severity}")
        
        for severity, threshold in config_data.severity_thresholds.items():
            if not isinstance(threshold, int) or threshold < 0:
                validation_results["errors"].append(f"Invalid threshold for {severity}: must be non-negative integer")
                validation_results["valid"] = False
    
    # Validate API settings
    if config_data.api_settings:
        if "rate_limiting" in config_data.api_settings:
            rate_config = config_data.api_settings["rate_limiting"]
            if "requests_per_hour" in rate_config:
                if not isinstance(rate_config["requests_per_hour"], int) or rate_config["requests_per_hour"] <= 0:
                    validation_results["errors"].append("requests_per_hour must be positive integer")
                    validation_results["valid"] = False
    
    return validation_results


@config_router.get("/export")
async def export_configuration(
    current_user: User = Depends(require_config_permission(Permission.CONFIG_READ))
):
    """Export current configuration as YAML"""
    
    import yaml
    from io import StringIO
    
    config_yaml = StringIO()
    yaml.dump(system_config, config_yaml, default_flow_style=False)
    
    return {
        "config_yaml": config_yaml.getvalue(),
        "exported_at": datetime.utcnow().isoformat(),
        "exported_by": current_user.username
    }


@config_router.post("/import")
async def import_configuration(
    config_yaml: str,
    current_user: User = Depends(require_config_permission(Permission.CONFIG_WRITE))
):
    """Import configuration from YAML"""
    
    try:
        import yaml
        imported_config = yaml.safe_load(config_yaml)
        
        # Validate imported configuration
        if not isinstance(imported_config, dict):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid YAML format"
            )
        
        # Update system configuration
        system_config.update(imported_config)
        
        return {
            "message": "Configuration imported successfully",
            "imported_at": datetime.utcnow().isoformat(),
            "imported_by": current_user.username
        }
    
    except yaml.YAMLError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid YAML: {str(e)}"
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to import configuration: {str(e)}"
        )


@config_router.get("/defaults")
async def get_default_configuration():
    """Get default configuration values"""
    
    return {
        "checkers": {
            "ssh": {
                "enabled": True,
                "check_key_auth": True,
                "check_root_login": False,
                "timeout": 30
            },
            "firewall": {
                "enabled": True,
                "check_status": True,
                "allowed_ports": [22, 80, 443]
            },
            "web_server": {
                "enabled": True,
                "check_ssl": True,
                "ssl_min_version": "TLSv1.2"
            }
        },
        "severity_thresholds": {
            "critical": 0,
            "high": 3,
            "medium": 10,
            "low": 20
        },
        "system_settings": {
            "scan_timeout": 300,
            "max_concurrent_scans": 5,
            "log_level": "INFO"
        }
    }