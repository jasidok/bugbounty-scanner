"""
Advanced Evidence Collection
Professional evidence gathering with integrity management
"""

import io
import hashlib
from pathlib import Path
from typing import Dict, Any
from datetime import datetime
from PIL import Image, ImageDraw

class EvidenceCollector:
    """Collect and manage evidence for vulnerabilities"""
    
    def __init__(self, project_dir: str):
        self.project_dir = Path(project_dir)
        self.evidence_dir = self.project_dir / 'evidence'
        self.evidence_dir.mkdir(exist_ok=True)
        
    def capture_screenshot(self, url: str, vulnerability_id: str) -> str:
        """Capture screenshot for web vulnerability"""
        # This would use tools like Selenium or Playwright
        # For now, create a placeholder
        screenshot_path = self.evidence_dir / f"{vulnerability_id}_screenshot.png"
        
        # Create a placeholder image
        img = Image.new('RGB', (1200, 800), color='white')
        draw = ImageDraw.Draw(img)
        draw.text((50, 50), f"Screenshot of {url}", fill='black')
        draw.text((50, 100), f"Vulnerability ID: {vulnerability_id}", fill='red')
        img.save(screenshot_path)
        
        return str(screenshot_path)
    
    def capture_http_request(self, request_data: Dict[str, Any], vulnerability_id: str) -> str:
        """Capture HTTP request/response for evidence"""
        evidence_file = self.evidence_dir / f"{vulnerability_id}_request.txt"
        
        with open(evidence_file, 'w') as f:
            f.write("HTTP Request Evidence\n")
            f.write("=" * 50 + "\n\n")
            f.write(f"URL: {request_data.get('url', 'N/A')}\n")
            f.write(f"Method: {request_data.get('method', 'N/A')}\n")
            f.write(f"Headers: {request_data.get('headers', {})}\n")
            f.write(f"Body: {request_data.get('body', 'N/A')}\n")
            f.write(f"Response Status: {request_data.get('status_code', 'N/A')}\n")
            f.write(f"Response Body: {request_data.get('response_body', 'N/A')}\n")
        
        return str(evidence_file)
    
    def capture_payload_evidence(self, payload: str, response: str, vulnerability_id: str) -> str:
        """Capture payload and response evidence"""
        evidence_file = self.evidence_dir / f"{vulnerability_id}_payload.txt"
        
        with open(evidence_file, 'w') as f:
            f.write("Payload Evidence\n")
            f.write("=" * 50 + "\n\n")
            f.write(f"Payload: {payload}\n")
            f.write("-" * 30 + "\n")
            f.write(f"Response: {response}\n")
        
        return str(evidence_file)
    
    def create_evidence_hash(self, evidence_file: str) -> str:
        """Create hash of evidence file for integrity"""
        with open(evidence_file, 'rb') as f:
            file_hash = hashlib.sha256(f.read()).hexdigest()
        
        hash_file = f"{evidence_file}.hash"
        with open(hash_file, 'w') as f:
            f.write(f"SHA256: {file_hash}\n")
            f.write(f"File: {evidence_file}\n")
            f.write(f"Created: {datetime.now().isoformat()}\n")
        
        return file_hash