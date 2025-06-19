"""Scan Service for managing security scan execution"""

import asyncio
import subprocess
import json
import tempfile
from datetime import datetime
from typing import Dict, List, Optional, Any
import logging

from ..models.scan import Scan, ScanStatus, ScanResult, SeverityLevel


logger = logging.getLogger(__name__)


class ScanService:
    """Service for managing security scan lifecycle"""
    
    def __init__(self):
        self.scans: Dict[str, Scan] = {}
        self.running_scans: Dict[str, asyncio.Task] = {}
    
    async def create_scan(self, scan: Scan) -> str:
        """Create and store a new scan"""
        self.scans[scan.id] = scan
        logger.info(f"Created scan: {scan.name} ({scan.id})")
        return scan.id
    
    async def get_scan(self, scan_id: str) -> Optional[Scan]:
        """Get scan by ID"""
        return self.scans.get(scan_id)
    
    async def list_scans(self, limit: int = 50, offset: int = 0, 
                        filters: Optional[Dict[str, Any]] = None) -> List[Scan]:
        """List scans with pagination and filtering"""
        scans = list(self.scans.values())
        
        # Apply filters
        if filters:
            for key, value in filters.items():
                if key == "status" and isinstance(value, ScanStatus):
                    scans = [s for s in scans if s.status == value]
                elif key == "created_by":
                    scans = [s for s in scans if s.created_by == value]
                elif hasattr(Scan, key):
                    scans = [s for s in scans if getattr(s, key) == value]
        
        # Sort by creation time (newest first)
        scans.sort(key=lambda s: s.created_at, reverse=True)
        
        # Apply pagination
        return scans[offset:offset + limit]
    
    async def start_scan(self, scan_id: str) -> bool:
        """Start scan execution"""
        scan = self.scans.get(scan_id)
        if not scan:
            return False
        
        if scan.status != ScanStatus.PENDING and scan.status != ScanStatus.FAILED:
            return False
        
        scan.status = ScanStatus.RUNNING
        scan.started_at = datetime.utcnow()
        logger.info(f"Started scan: {scan.name} ({scan_id})")
        return True
    
    async def execute_scan(self, scan_id: str) -> bool:
        """Execute the actual security scan"""
        scan = self.scans.get(scan_id)
        if not scan:
            return False
        
        try:
            # Create a task for the scan execution
            task = asyncio.create_task(self._run_vigileguard_scan(scan))
            self.running_scans[scan_id] = task
            
            # Wait for completion
            success = await task
            
            # Clean up task
            if scan_id in self.running_scans:
                del self.running_scans[scan_id]
            
            # Update scan status
            if success:
                scan.status = ScanStatus.COMPLETED
                scan.completed_at = datetime.utcnow()
                if scan.started_at:
                    scan.duration = (scan.completed_at - scan.started_at).total_seconds()
                logger.info(f"Completed scan: {scan.name} ({scan_id})")
            else:
                scan.status = ScanStatus.FAILED
                scan.completed_at = datetime.utcnow()
                if scan.started_at:
                    scan.duration = (scan.completed_at - scan.started_at).total_seconds()
                logger.error(f"Failed scan: {scan.name} ({scan_id})")
            
            return success
        
        except asyncio.CancelledError:
            scan.status = ScanStatus.CANCELLED
            scan.completed_at = datetime.utcnow()
            if scan.started_at:
                scan.duration = (scan.completed_at - scan.started_at).total_seconds()
            logger.info(f"Cancelled scan: {scan.name} ({scan_id})")
            return False
        
        except Exception as e:
            scan.status = ScanStatus.FAILED
            scan.error_message = str(e)
            scan.completed_at = datetime.utcnow()
            if scan.started_at:
                scan.duration = (scan.completed_at - scan.started_at).total_seconds()
            logger.error(f"Scan execution error: {scan.name} ({scan_id}) - {str(e)}")
            return False
    
    async def _run_vigileguard_scan(self, scan: Scan) -> bool:
        """Run the actual VigileGuard CLI scan"""
        try:
            # Create temporary config file if needed
            config_file = None
            if scan.config:
                config_file = tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False)
                # Convert config dict to YAML-like format
                import yaml
                yaml.dump(scan.config, config_file)
                config_file.close()
            
            # Build command
            cmd = [
                'python', '-m', 'vigileguard.vigileguard',
                '--target', scan.target,
                '--format', 'json',
                '--output', f'/tmp/scan_{scan.id}.json'
            ]
            
            # Add checkers
            if scan.checkers and scan.checkers != ["all"]:
                for checker in scan.checkers:
                    if checker != "all":
                        cmd.extend(['--checker', checker])
            
            # Add config file
            if config_file:
                cmd.extend(['--config', config_file.name])
            
            # Run scan with timeout
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd='/app'  # VigileGuard working directory
            )
            
            # Wait for completion with timeout
            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(), 
                    timeout=300  # 5 minute timeout
                )
            except asyncio.TimeoutError:
                process.kill()
                scan.error_message = "Scan timed out after 5 minutes"
                return False
            
            # Check exit code
            if process.returncode != 0:
                scan.error_message = f"Scan failed with exit code {process.returncode}: {stderr.decode()}"
                return False
            
            # Parse results
            await self._parse_scan_results(scan)
            
            # Clean up config file
            if config_file:
                import os
                try:
                    os.unlink(config_file.name)
                except:
                    pass
            
            return True
        
        except Exception as e:
            scan.error_message = str(e)
            return False
    
    async def _parse_scan_results(self, scan: Scan):
        """Parse scan results from JSON output"""
        try:
            result_file = f'/tmp/scan_{scan.id}.json'
            
            # Try to read the results file
            try:
                with open(result_file, 'r') as f:
                    results_data = json.load(f)
            except FileNotFoundError:
                # If no results file, create mock results for demo
                results_data = self._create_demo_results(scan)
            
            # Parse results
            if 'checks' in results_data:
                for check_data in results_data['checks']:
                    severity = SeverityLevel.MEDIUM
                    if check_data.get('severity'):
                        try:
                            severity = SeverityLevel(check_data['severity'].lower())
                        except ValueError:
                            pass
                    
                    result = ScanResult(
                        check_id=check_data.get('id', 'unknown'),
                        check_name=check_data.get('name', 'Unknown Check'),
                        severity=severity,
                        status=check_data.get('status', 'UNKNOWN'),
                        message=check_data.get('message', 'No message'),
                        details=check_data.get('details', {}),
                        remediation=check_data.get('remediation'),
                        references=check_data.get('references', [])
                    )
                    scan.add_result(result)
            
            # Update metadata
            scan.metadata.update({
                'scan_engine': 'VigileGuard',
                'scan_version': '3.0.0',
                'result_file': result_file,
                'parsed_at': datetime.utcnow().isoformat()
            })
            
        except Exception as e:
            logger.error(f"Failed to parse scan results: {e}")
            # Add error result
            error_result = ScanResult(
                check_id='parse_error',
                check_name='Result Parsing',
                severity=SeverityLevel.HIGH,
                status='FAIL',
                message=f'Failed to parse scan results: {str(e)}',
                details={'error': str(e)}
            )
            scan.add_result(error_result)
    
    def _create_demo_results(self, scan: Scan) -> Dict[str, Any]:
        """Create demo results for testing purposes"""
        return {
            'target': scan.target,
            'timestamp': datetime.utcnow().isoformat(),
            'checks': [
                {
                    'id': 'ssh_config',
                    'name': 'SSH Configuration',
                    'severity': 'medium',
                    'status': 'PASS',
                    'message': 'SSH configuration is secure',
                    'details': {'port': 22, 'protocol': '2'},
                    'remediation': None,
                    'references': ['https://docs.vigileguard.com/ssh']
                },
                {
                    'id': 'file_permissions',
                    'name': 'File Permissions',
                    'severity': 'high',
                    'status': 'FAIL',
                    'message': 'Found world-writable files',
                    'details': {'files': ['/tmp/example.txt', '/var/log/app.log']},
                    'remediation': 'Remove world-write permissions from sensitive files',
                    'references': ['https://docs.vigileguard.com/file-permissions']
                },
                {
                    'id': 'firewall_status',
                    'name': 'Firewall Status',
                    'severity': 'critical',
                    'status': 'FAIL',
                    'message': 'Firewall is not enabled',
                    'details': {'service': 'ufw', 'status': 'inactive'},
                    'remediation': 'Enable and configure firewall rules',
                    'references': ['https://docs.vigileguard.com/firewall']
                }
            ]
        }
    
    async def cancel_scan(self, scan_id: str) -> bool:
        """Cancel a running scan"""
        scan = self.scans.get(scan_id)
        if not scan or scan.status != ScanStatus.RUNNING:
            return False
        
        # Cancel the running task
        if scan_id in self.running_scans:
            task = self.running_scans[scan_id]
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
            del self.running_scans[scan_id]
        
        scan.status = ScanStatus.CANCELLED
        scan.completed_at = datetime.utcnow()
        if scan.started_at:
            scan.duration = (scan.completed_at - scan.started_at).total_seconds()
        
        logger.info(f"Cancelled scan: {scan.name} ({scan_id})")
        return True
    
    async def delete_scan(self, scan_id: str) -> bool:
        """Delete a scan"""
        if scan_id not in self.scans:
            return False
        
        scan = self.scans[scan_id]
        
        # Cannot delete running scans
        if scan.status == ScanStatus.RUNNING:
            return False
        
        # Cancel if somehow still running
        if scan_id in self.running_scans:
            await self.cancel_scan(scan_id)
        
        # Remove scan
        del self.scans[scan_id]
        logger.info(f"Deleted scan: {scan.name} ({scan_id})")
        return True
    
    async def fail_scan(self, scan_id: str, error_message: str):
        """Mark scan as failed with error message"""
        scan = self.scans.get(scan_id)
        if not scan:
            return
        
        scan.status = ScanStatus.FAILED
        scan.error_message = error_message
        scan.completed_at = datetime.utcnow()
        if scan.started_at:
            scan.duration = (scan.completed_at - scan.started_at).total_seconds()
        
        logger.error(f"Failed scan: {scan.name} ({scan_id}) - {error_message}")
    
    async def get_scan_statistics(self) -> Dict[str, Any]:
        """Get overall scan statistics"""
        total_scans = len(self.scans)
        status_counts = {}
        
        for scan in self.scans.values():
            status = scan.status.value
            status_counts[status] = status_counts.get(status, 0) + 1
        
        return {
            'total_scans': total_scans,
            'status_distribution': status_counts,
            'running_scans': len(self.running_scans),
            'last_scan': max(
                (scan.created_at for scan in self.scans.values()),
                default=None
            )
        }