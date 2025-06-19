#!/usr/bin/env python3
"""
Container Security Checkers for VigileGuard
===========================================

This module provides security checkers for containerized environments including
Docker, Podman, and container runtime security analysis.

Author: VigileGuard Development Team
License: MIT
"""

import os
import re
import json
import subprocess
import yaml
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from enum import Enum

try:
    from .vigileguard import Finding, SeverityLevel, SecurityChecker
except ImportError:
    # Fallback for standalone usage
    import sys
    sys.path.append(os.path.dirname(os.path.abspath(__file__)))
    from vigileguard import Finding, SeverityLevel, SecurityChecker


class ContainerRuntime(Enum):
    """Container runtime types"""
    DOCKER = "docker"
    PODMAN = "podman"
    CONTAINERD = "containerd"
    CRI_O = "cri-o"


@dataclass
class ContainerInfo:
    """Container information"""
    id: str
    name: str
    image: str
    status: str
    ports: List[str]
    mounts: List[str]
    privileged: bool
    user: str
    capabilities: List[str]


class DockerSecurityChecker(SecurityChecker):
    """Docker-specific security checker"""
    
    def __init__(self):
        super().__init__()
        self.docker_available = self._check_docker_available()
        self.daemon_config_path = "/etc/docker/daemon.json"
    
    def _check_docker_available(self) -> bool:
        """Check if Docker is available"""
        try:
            result = subprocess.run(['docker', '--version'], 
                                  capture_output=True, text=True, timeout=10)
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False
    
    def _run_docker_command(self, command: List[str]) -> Optional[str]:
        """Run Docker command safely"""
        try:
            result = subprocess.run(['docker'] + command, 
                                  capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                return result.stdout.strip()
            return None
        except (subprocess.TimeoutExpired, subprocess.SubprocessError):
            return None
    
    def check_daemon_configuration(self):
        """Check Docker daemon configuration"""
        if not self.docker_available:
            return
        
        # Check daemon configuration file
        if os.path.exists(self.daemon_config_path):
            try:
                with open(self.daemon_config_path, 'r') as f:
                    config = json.load(f)
                
                # Check for security configurations
                security_issues = []
                
                # Check if user namespace remapping is enabled
                if not config.get('userns-remap'):
                    security_issues.append("User namespace remapping not enabled")
                
                # Check if live restore is enabled
                if not config.get('live-restore', False):
                    security_issues.append("Live restore not enabled")
                
                # Check logging configuration
                if not config.get('log-driver'):
                    security_issues.append("Logging driver not configured")
                
                # Check if experimental features are disabled
                if config.get('experimental', False):
                    security_issues.append("Experimental features enabled")
                
                # Check if insecure registries are configured
                if config.get('insecure-registries'):
                    security_issues.append("Insecure registries configured")
                
                if security_issues:
                    self.findings.append(Finding(
                        category="Container Security",
                        severity=SeverityLevel.MEDIUM,
                        title="Docker daemon configuration issues",
                        description=f"Found {len(security_issues)} Docker daemon configuration issues",
                        recommendation="Review and harden Docker daemon configuration",
                        details={
                            "config_file": self.daemon_config_path,
                            "issues": security_issues,
                            "config": config
                        }
                    ))
            except (json.JSONDecodeError, IOError) as e:
                self.findings.append(Finding(
                    category="Container Security",
                    severity=SeverityLevel.LOW,
                    title="Docker daemon configuration file issues",
                    description=f"Cannot read Docker daemon configuration: {e}",
                    recommendation="Ensure Docker daemon configuration file is valid JSON",
                    details={"config_file": self.daemon_config_path, "error": str(e)}
                ))
        else:
            self.findings.append(Finding(
                category="Container Security",
                severity=SeverityLevel.MEDIUM,
                title="Docker daemon configuration file missing",
                description="No Docker daemon configuration file found",
                recommendation="Create /etc/docker/daemon.json with security hardening settings",
                details={"expected_path": self.daemon_config_path}
            ))
    
    def check_running_containers(self):
        """Analyze running containers for security issues"""
        if not self.docker_available:
            return
        
        # Get container information
        containers_json = self._run_docker_command(['ps', '-a', '--format', 'json'])
        if not containers_json:
            return
        
        containers = []
        privileged_containers = []
        root_containers = []
        exposed_containers = []
        
        for line in containers_json.split('\n'):
            if line.strip():
                try:
                    container = json.loads(line)
                    containers.append(container)
                    
                    # Check for privileged containers
                    inspect_result = self._run_docker_command(['inspect', container.get('ID', '')])
                    if inspect_result:
                        inspect_data = json.loads(inspect_result)[0]
                        host_config = inspect_data.get('HostConfig', {})
                        config = inspect_data.get('Config', {})
                        
                        # Check privileged mode
                        if host_config.get('Privileged', False):
                            privileged_containers.append(container.get('Names', 'unknown'))
                        
                        # Check if running as root
                        user = config.get('User', 'root')
                        if not user or user == 'root' or user == '0':
                            root_containers.append(container.get('Names', 'unknown'))
                        
                        # Check for exposed ports
                        ports = container.get('Ports', '')
                        if '0.0.0.0:' in ports:
                            exposed_containers.append({
                                'name': container.get('Names', 'unknown'),
                                'ports': ports
                            })
                            
                except json.JSONDecodeError:
                    continue
        
        # Report privileged containers
        if privileged_containers:
            self.findings.append(Finding(
                category="Container Security",
                severity=SeverityLevel.CRITICAL,
                title="Privileged containers detected",
                description=f"Found {len(privileged_containers)} containers running in privileged mode",
                recommendation="Remove --privileged flag and use specific capabilities instead",
                details={
                    "privileged_containers": privileged_containers,
                    "total_containers": len(containers)
                }
            ))
        
        # Report containers running as root
        if root_containers:
            self.findings.append(Finding(
                category="Container Security",
                severity=SeverityLevel.HIGH,
                title="Containers running as root user",
                description=f"Found {len(root_containers)} containers running as root",
                recommendation="Create non-root users in container images and use USER directive",
                details={
                    "root_containers": root_containers,
                    "total_containers": len(containers)
                }
            ))
        
        # Report containers with exposed ports
        if exposed_containers:
            self.findings.append(Finding(
                category="Container Security",
                severity=SeverityLevel.MEDIUM,
                title="Containers with publicly exposed ports",
                description=f"Found {len(exposed_containers)} containers with ports exposed to 0.0.0.0",
                recommendation="Bind ports to specific interfaces or use reverse proxy",
                details={
                    "exposed_containers": exposed_containers,
                    "total_containers": len(containers)
                }
            ))
    
    def check_docker_socket_permissions(self):
        """Check Docker socket permissions"""
        socket_path = "/var/run/docker.sock"
        
        if os.path.exists(socket_path):
            stat_info = os.stat(socket_path)
            permissions = oct(stat_info.st_mode)[-3:]
            
            # Check if socket is world-accessible
            if permissions[-1] in ['6', '7']:  # Others have write permission
                self.findings.append(Finding(
                    category="Container Security",
                    severity=SeverityLevel.CRITICAL,
                    title="Docker socket has insecure permissions",
                    description=f"Docker socket permissions ({permissions}) allow world access",
                    recommendation="Set proper permissions: sudo chmod 660 /var/run/docker.sock",
                    details={
                        "socket_path": socket_path,
                        "current_permissions": permissions,
                        "recommended_permissions": "660"
                    }
                ))
    
    def check_docker_images(self):
        """Check Docker images for security issues"""
        if not self.docker_available:
            return
        
        # Get image information
        images_result = self._run_docker_command(['images', '--format', 'json'])
        if not images_result:
            return
        
        outdated_images = []
        untagged_images = []
        large_images = []
        
        for line in images_result.split('\n'):
            if line.strip():
                try:
                    image = json.loads(line)
                    
                    # Check for untagged images
                    tag = image.get('Tag', '')
                    if tag == '<none>':
                        untagged_images.append(image.get('Repository', 'unknown'))
                    
                    # Check for large images (>1GB)
                    size_str = image.get('Size', '0B')
                    if 'GB' in size_str:
                        try:
                            size_gb = float(size_str.replace('GB', '').strip())
                            if size_gb > 1.0:
                                large_images.append({
                                    'repository': image.get('Repository', 'unknown'),
                                    'tag': tag,
                                    'size': size_str
                                })
                        except ValueError:
                            pass
                            
                except json.JSONDecodeError:
                    continue
        
        # Report untagged images
        if untagged_images:
            self.findings.append(Finding(
                category="Container Security",
                severity=SeverityLevel.LOW,
                title="Untagged Docker images found",
                description=f"Found {len(untagged_images)} untagged (dangling) images",
                recommendation="Remove unused images: docker image prune",
                details={"untagged_images": untagged_images}
            ))
        
        # Report large images
        if large_images:
            self.findings.append(Finding(
                category="Container Security",
                severity=SeverityLevel.MEDIUM,
                title="Large Docker images detected",
                description=f"Found {len(large_images)} images larger than 1GB",
                recommendation="Use multi-stage builds and minimal base images to reduce attack surface",
                details={"large_images": large_images}
            ))
    
    def run(self):
        """Run all Docker security checks"""
        if not self.docker_available:
            self.findings.append(Finding(
                category="Container Security",
                severity=SeverityLevel.INFO,
                title="Docker not available",
                description="Docker is not installed or not accessible",
                recommendation="Install Docker if containerization is used",
                details={"status": "not_available"}
            ))
            return
        
        self.check_daemon_configuration()
        self.check_running_containers()
        self.check_docker_socket_permissions()
        self.check_docker_images()


class PodmanSecurityChecker(SecurityChecker):
    """Podman-specific security checker"""
    
    def __init__(self):
        super().__init__()
        self.podman_available = self._check_podman_available()
    
    def _check_podman_available(self) -> bool:
        """Check if Podman is available"""
        try:
            result = subprocess.run(['podman', '--version'], 
                                  capture_output=True, text=True, timeout=10)
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False
    
    def run(self):
        """Run all Podman security checks"""
        if not self.podman_available:
            self.findings.append(Finding(
                category="Container Security",
                severity=SeverityLevel.INFO,
                title="Podman not available",
                description="Podman is not installed or not accessible",
                recommendation="Consider Podman as a rootless container alternative",
                details={"status": "not_available"}
            ))
            return
        
        # Add Podman-specific checks here
        self.findings.append(Finding(
            category="Container Security",
            severity=SeverityLevel.INFO,
            title="Podman container runtime detected",
            description="Podman rootless container runtime is available",
            recommendation="Ensure Podman is properly configured for security",
            details={"runtime": "podman"}
        ))


class ContainerSecurityChecker(SecurityChecker):
    """Main container security checker that orchestrates all container checks"""
    
    def __init__(self):
        super().__init__()
        self.docker_checker = DockerSecurityChecker()
        self.podman_checker = PodmanSecurityChecker()
    
    def check_container_runtimes(self):
        """Check which container runtimes are available"""
        runtimes = []
        
        # Check Docker
        if self.docker_checker.docker_available:
            runtimes.append("Docker")
        
        # Check Podman
        if self.podman_checker.podman_available:
            runtimes.append("Podman")
        
        if runtimes:
            self.findings.append(Finding(
                category="Container Security",
                severity=SeverityLevel.INFO,
                title="Container runtimes detected",
                description=f"Found container runtimes: {', '.join(runtimes)}",
                recommendation="Ensure all container runtimes are properly secured",
                details={"runtimes": runtimes}
            ))
        else:
            self.findings.append(Finding(
                category="Container Security",
                severity=SeverityLevel.INFO,
                title="No container runtimes detected",
                description="No container runtimes (Docker, Podman) found on system",
                recommendation="Container security checks skipped",
                details={"runtimes": []}
            ))
    
    def run(self):
        """Run all container security checks"""
        self.check_container_runtimes()
        
        # Run Docker checks
        self.docker_checker.run()
        self.findings.extend(self.docker_checker.findings)
        
        # Run Podman checks
        self.podman_checker.run()
        self.findings.extend(self.podman_checker.findings)
    
    def check(self):
        """Compatibility method for VigileGuard integration"""
        self.run()
        return self.findings


def main():
    """Main function for standalone testing"""
    checker = ContainerSecurityChecker()
    checker.run()
    
    print(f"🐳 Container Security Analysis Results:")
    print(f"Found {len(checker.findings)} findings")
    
    for finding in checker.findings:
        print(f"\n[{finding.severity.value}] {finding.title}")
        print(f"Description: {finding.description}")
        print(f"Recommendation: {finding.recommendation}")


if __name__ == "__main__":
    main()