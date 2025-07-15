"""
Automation and Orchestration
Advanced automation features for bug bounty workflows
"""

import asyncio
import aiohttp
import schedule
import time
import threading
import hashlib
import json
import smtplib
from typing import Dict, List, Any, Callable, Optional
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import logging

logger = logging.getLogger(__name__)

@dataclass
class AutomationTask:
    """Represents an automation task"""
    id: str
    name: str
    description: str
    schedule: str  # cron-like schedule
    action: Callable
    params: Dict[str, Any]
    enabled: bool = True
    last_run: Optional[datetime] = None
    next_run: Optional[datetime] = None

class NotificationManager:
    """Manage notifications for findings"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.email_config = config.get('email', {})
        self.slack_config = config.get('slack', {})
        self.discord_config = config.get('discord', {})
    
    def send_email_notification(self, finding: Dict[str, Any], recipients: List[str]):
        """Send email notification for new finding"""
        if not self.email_config.get('enabled', False):
            return
        
        subject = f"New {finding.get('severity', 'Unknown')} Vulnerability Found: {finding.get('vulnerability_type', 'Unknown')}"
        body = f"""
A new vulnerability has been discovered:

Target: {finding.get('target', 'Unknown')}
Type: {finding.get('vulnerability_type', 'Unknown')}
Severity: {finding.get('severity', 'Unknown')}
Confidence: {finding.get('confidence', 'Unknown')}
Tool: {finding.get('tool_used', 'Unknown')}
Discovered: {finding.get('timestamp', 'Unknown')}

Description:
{finding.get('description', 'No description available')}

Evidence:
{finding.get('evidence', 'No evidence available')}

Recommendations:
{finding.get('recommendations', 'No recommendations available')}

Please investigate and remediate as appropriate.
"""
        
        msg = MIMEMultipart()
        msg['From'] = self.email_config['from']
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain'))
        
        try:
            server = smtplib.SMTP(self.email_config['smtp_server'], self.email_config['smtp_port'])
            if self.email_config.get('use_tls', True):
                server.starttls()
            
            server.login(self.email_config['username'], self.email_config['password'])
            
            for recipient in recipients:
                msg['To'] = recipient
                server.sendmail(self.email_config['from'], recipient, msg.as_string())
            
            server.quit()
            logger.info(f"Email notification sent for {finding.get('vulnerability_type', 'Unknown')}")
        except Exception as e:
            logger.error(f"Failed to send email notification: {e}")
    
    async def send_slack_notification(self, finding: Dict[str, Any], webhook_url: str):
        """Send Slack notification for new finding"""
        if not self.slack_config.get('enabled', False):
            return
        
        color = {
            'Critical': 'danger',
            'High': 'warning',
            'Medium': 'warning',
            'Low': 'good',
            'Info': 'good'
        }.get(finding.get('severity', 'Unknown'), 'good')
        
        payload = {
            "text": f"New {finding.get('severity', 'Unknown')} Vulnerability Found",
            "attachments": [
                {
                    "color": color,
                    "fields": [
                        {"title": "Target", "value": finding.get('target', 'Unknown'), "short": True},
                        {"title": "Type", "value": finding.get('vulnerability_type', 'Unknown'), "short": True},
                        {"title": "Severity", "value": finding.get('severity', 'Unknown'), "short": True},
                        {"title": "Tool", "value": finding.get('tool_used', 'Unknown'), "short": True},
                        {"title": "Description", "value": finding.get('description', 'No description'), "short": False},
                        {"title": "Recommendations", "value": finding.get('recommendations', 'No recommendations'), "short": False}
                    ]
                }
            ]
        }
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(webhook_url, json=payload) as response:
                    if response.status == 200:
                        logger.info(f"Slack notification sent for {finding.get('vulnerability_type', 'Unknown')}")
                    else:
                        logger.error(f"Failed to send Slack notification: {response.status}")
        except Exception as e:
            logger.error(f"Failed to send Slack notification: {e}")

class AutomationEngine:
    """Orchestrate automated bug bounty workflows"""
    
    def __init__(self, scanner):
        self.scanner = scanner
        self.tasks: Dict[str, AutomationTask] = {}
        self.notification_manager = NotificationManager({})
        self.executor = ThreadPoolExecutor(max_workers=5)
        self.running = False
        self.scheduler_thread = None
    
    def add_task(self, task: AutomationTask):
        """Add automation task"""
        self.tasks[task.id] = task
        logger.info(f"Added automation task: {task.name}")
    
    def remove_task(self, task_id: str):
        """Remove automation task"""
        if task_id in self.tasks:
            del self.tasks[task_id]
            logger.info(f"Removed automation task: {task_id}")
    
    def start(self):
        """Start automation engine"""
        if self.running:
            return
        
        self.running = True
        self.scheduler_thread = threading.Thread(target=self._scheduler_loop)
        self.scheduler_thread.daemon = True
        self.scheduler_thread.start()
        logger.info("Automation engine started")
    
    def stop(self):
        """Stop automation engine"""
        self.running = False
        if self.scheduler_thread:
            self.scheduler_thread.join()
        logger.info("Automation engine stopped")
    
    def _scheduler_loop(self):
        """Main scheduler loop"""
        while self.running:
            try:
                self._check_and_run_tasks()
                time.sleep(60)  # Check every minute
            except Exception as e:
                logger.error(f"Scheduler error: {e}")
    
    def _check_and_run_tasks(self):
        """Check and run scheduled tasks"""
        current_time = datetime.now()
        
        for task in self.tasks.values():
            if not task.enabled:
                continue
            
            if task.next_run and current_time >= task.next_run:
                logger.info(f"Running scheduled task: {task.name}")
                
                try:
                    # Run task in thread pool
                    future = self.executor.submit(task.action, **task.params)
                    
                    # Update task timing
                    task.last_run = current_time
                    task.next_run = self._calculate_next_run(task.schedule, current_time)
                    
                except Exception as e:
                    logger.error(f"Task execution error: {e}")
    
    def _calculate_next_run(self, schedule: str, current_time: datetime) -> datetime:
        """Calculate next run time based on schedule"""
        # Simple schedule parsing - in production use croniter or similar
        if schedule == 'hourly':
            return current_time + timedelta(hours=1)
        elif schedule == 'daily':
            return current_time + timedelta(days=1)
        elif schedule == 'weekly':
            return current_time + timedelta(weeks=1)
        else:
            return current_time + timedelta(hours=1)  # Default to hourly
    
    def create_monitoring_task(self, program_url: str, check_interval: str = 'daily') -> AutomationTask:
        """Create continuous monitoring task"""
        task = AutomationTask(
            id=f"monitor_{hashlib.md5(program_url.encode()).hexdigest()[:8]}",
            name=f"Monitor {program_url}",
            description=f"Continuous monitoring of {program_url}",
            schedule=check_interval,
            action=self._monitor_program,
            params={'program_url': program_url},
            next_run=datetime.now() + timedelta(minutes=5)  # Start in 5 minutes
        )
        
        self.add_task(task)
        return task
    
    def _monitor_program(self, program_url: str):
        """Monitor program for new vulnerabilities"""
        try:
            # Run scan
            results = self.scanner.scan_program(program_url)
            
            # Check for new findings
            new_findings = self._check_for_new_findings(results)
            
            # Send notifications for new findings
            for finding in new_findings:
                if finding.get('severity') in ['Critical', 'High']:
                    self.notification_manager.send_email_notification(
                        finding, 
                        ['security@example.com']
                    )
            
            logger.info(f"Monitoring completed for {program_url}. Found {len(new_findings)} new issues.")
            
        except Exception as e:
            logger.error(f"Monitoring error for {program_url}: {e}")
    
    def _check_for_new_findings(self, scan_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check for new findings compared to previous scans"""
        # This would compare against previous results stored in database
        # For now, return empty list
        return []

class ContinuousScanner:
    """Continuous scanning capabilities"""
    
    def __init__(self, scanner):
        self.scanner = scanner
        self.active_scans: Dict[str, Dict[str, Any]] = {}
        self.scan_history: List[Dict[str, Any]] = []
    
    async def start_continuous_scan(self, program_url: str, interval_hours: int = 24):
        """Start continuous scanning of a program"""
        scan_id = f"continuous_{hashlib.md5(program_url.encode()).hexdigest()[:8]}"
        
        self.active_scans[scan_id] = {
            'program_url': program_url,
            'interval_hours': interval_hours,
            'started': datetime.now(),
            'last_scan': None,
            'next_scan': datetime.now(),
            'total_scans': 0,
            'findings_count': 0
        }
        
        logger.info(f"Started continuous scan for {program_url} (every {interval_hours} hours)")
        
        # Start background task
        asyncio.create_task(self._continuous_scan_loop(scan_id))
    
    async def _continuous_scan_loop(self, scan_id: str):
        """Continuous scanning loop"""
        while scan_id in self.active_scans:
            scan_config = self.active_scans[scan_id]
            
            if datetime.now() >= scan_config['next_scan']:
                try:
                    logger.info(f"Running continuous scan: {scan_id}")
                    
                    # Run scan
                    results = self.scanner.scan_program(scan_config['program_url'])
                    
                    # Update scan statistics
                    scan_config['last_scan'] = datetime.now()
                    scan_config['next_scan'] = datetime.now() + timedelta(hours=scan_config['interval_hours'])
                    scan_config['total_scans'] += 1
                    scan_config['findings_count'] += results.get('results_count', 0)
                    
                    # Store scan history
                    self.scan_history.append({
                        'scan_id': scan_id,
                        'timestamp': datetime.now(),
                        'results': results
                    })
                    
                    # Limit history size
                    if len(self.scan_history) > 100:
                        self.scan_history = self.scan_history[-100:]
                    
                    logger.info(f"Continuous scan completed: {scan_id}")
                    
                except Exception as e:
                    logger.error(f"Continuous scan error: {e}")
            
            await asyncio.sleep(300)  # Check every 5 minutes
    
    def stop_continuous_scan(self, scan_id: str):
        """Stop continuous scan"""
        if scan_id in self.active_scans:
            del self.active_scans[scan_id]
            logger.info(f"Stopped continuous scan: {scan_id}")
    
    def get_scan_status(self) -> Dict[str, Any]:
        """Get status of all continuous scans"""
        return {
            'active_scans': len(self.active_scans),
            'scans': {
                scan_id: {
                    'program_url': config['program_url'],
                    'interval_hours': config['interval_hours'],
                    'started': config['started'].isoformat(),
                    'last_scan': config['last_scan'].isoformat() if config['last_scan'] else None,
                    'next_scan': config['next_scan'].isoformat(),
                    'total_scans': config['total_scans'],
                    'findings_count': config['findings_count']
                }
                for scan_id, config in self.active_scans.items()
            }
        }