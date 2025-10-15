#!/usr/bin/env python3

import os
import subprocess
import threading
import shutil
import re
import sys
import argparse
import time
import json
import smtplib
import requests
import platform
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from pathlib import Path
from colorama import Fore, Style, init
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
import google.generativeai as genai

init(autoreset=True)

HEADER = f"""{Fore.GREEN}
╔════════════════════════════════════════╗
║           (⌐■_■) ENHANCED RECON        ║
║          FRAMEWORK v4.1                ║
║        Coded by Ketaxpl0it             ║
║    Gemini AI-Powered Bug Bounty        ║
╚════════════════════════════════════════╝

{Fore.CYAN}  ~ Gemini AI-Enhanced Bug Bounty Recon Automation ~
"""

class GeminiAnalyzer:
    """Gemini AI-powered analysis and risk assessment"""
    
    def __init__(self, api_key=None):
        self.api_key = api_key
        self.model = None
        
        if api_key:
            try:
                genai.configure(api_key=api_key)
                self.model = genai.GenerativeModel('gemini-pro')
            except Exception as e:
                print(f"{Fore.YELLOW}[!] Gemini AI configuration failed: {e}")
    
    def analyze_endpoint_with_ai(self, endpoint):
        """Use Gemini AI to analyze endpoint for security risks"""
        if not self.model:
            return RiskAnalyzer.analyze_endpoint_risk_detailed(endpoint)
        
        try:
            prompt = f"""
            Analyze this URL/endpoint for potential security vulnerabilities and assign a risk score from 1-10:
            
            URL: {endpoint}
            
            Consider:
            - SQL injection possibilities
            - XSS vulnerabilities
            - Directory traversal risks
            - Authentication bypass potential
            - Information disclosure
            - Admin/sensitive areas
            - File upload vulnerabilities
            
            Respond with:
            1. Risk Score (1-10)
            2. Brief explanation of risks
            3. Recommended testing approach
            
            Format: RISK_SCORE: X | EXPLANATION: ... | TESTING: ...
            """
            
            response = self.model.generate_content(prompt)
            return self._parse_ai_response(response.text, endpoint)
            
        except Exception as e:
            print(f"{Fore.YELLOW}[!] Gemini AI analysis failed for {endpoint}: {e}")
            return RiskAnalyzer.analyze_endpoint_risk_detailed(endpoint)
    
    def _parse_ai_response(self, response, endpoint):
        """Parse Gemini AI response and extract risk score"""
        try:
            # Extract risk score
            risk_match = re.search(r'RISK_SCORE:\s*(\d+)', response)
            risk_score = int(risk_match.group(1)) if risk_match else 5
            
            # Extract explanation
            explanation_match = re.search(r'EXPLANATION:\s*([^|]+)', response)
            explanation = explanation_match.group(1).strip() if explanation_match else "AI analysis completed"
            
            # Extract testing approach
            testing_match = re.search(r'TESTING:\s*(.+)', response)
            testing = testing_match.group(1).strip() if testing_match else "Manual testing recommended"
            
            return {
                'endpoint': endpoint,
                'risk_score': min(max(risk_score, 1), 10),
                'ai_explanation': explanation,
                'testing_approach': testing,
                'analysis_type': 'gemini_ai'
            }
        except Exception:
            return RiskAnalyzer.analyze_endpoint_risk_detailed(endpoint)
    
    def analyze_javascript_content(self, js_content, url):
        """Use Gemini AI to analyze JavaScript content"""
        if not self.model or len(js_content) > 10000:
            return RiskAnalyzer.analyze_js_endpoint(js_content)
        
        try:
            prompt = f"""
            Analyze this JavaScript code for security vulnerabilities and interesting endpoints:
            
            Source URL: {url}
            JavaScript Content (first 5000 chars):
            {js_content[:5000]}
            
            Find:
            1. API endpoints
            2. Authentication tokens/secrets
            3. Hardcoded credentials
            4. Vulnerable functions
            5. Internal URLs/domains
            
            Format each finding as: TYPE: description | RISK: 1-10 | ENDPOINT: url_if_applicable
            """
            
            response = self.model.generate_content(prompt)
            return self._parse_js_analysis(response.text, url)
            
        except Exception as e:
            print(f"{Fore.YELLOW}[!] Gemini JS analysis failed: {e}")
            return RiskAnalyzer.analyze_js_endpoint(js_content)
    
    def _parse_js_analysis(self, response, source_url):
        """Parse JavaScript analysis response"""
        findings = []
        lines = response.split('\n')
        
        for line in lines:
            if 'TYPE:' in line and 'RISK:' in line:
                try:
                    type_match = re.search(r'TYPE:\s*([^|]+)', line)
                    risk_match = re.search(r'RISK:\s*(\d+)', line)
                    endpoint_match = re.search(r'ENDPOINT:\s*(.+)', line)
                    
                    if type_match and risk_match:
                        finding = {
                            'type': type_match.group(1).strip(),
                            'risk_score': int(risk_match.group(1)),
                            'endpoint': endpoint_match.group(1).strip() if endpoint_match else source_url,
                            'source_url': source_url
                        }
                        findings.append(finding)
                except Exception:
                    continue
        
        return findings if findings else RiskAnalyzer.analyze_js_endpoint("")

class ToolInstaller:
    """Enhanced automatic installation of reconnaissance tools"""
    
    # Updated with latest installation methods and verified URLs
    TOOL_INSTALL_COMMANDS = {
        'ubuntu': {
            'subfinder': 'curl -sSfL https://raw.githubusercontent.com/projectdiscovery/subfinder/main/install.sh | sh -s -- -b /usr/local/bin',
            'amass': 'snap install amass || (wget https://github.com/owasp-amass/amass/releases/latest/download/amass_linux_amd64.zip -O /tmp/amass.zip && unzip /tmp/amass.zip -d /tmp && sudo mv /tmp/amass_linux_amd64/amass /usr/local/bin/ && rm -rf /tmp/amass*)',
            'dnsx': 'curl -sSfL https://raw.githubusercontent.com/projectdiscovery/dnsx/main/install.sh | sh -s -- -b /usr/local/bin',
            'httpx': 'curl -sSfL https://raw.githubusercontent.com/projectdiscovery/httpx/main/install.sh | sh -s -- -b /usr/local/bin',
            'nmap': 'sudo apt-get update && sudo apt-get install -y nmap',
            'naabu': 'curl -sSfL https://raw.githubusercontent.com/projectdiscovery/naabu/main/install.sh | sh -s -- -b /usr/local/bin',
            'feroxbuster': 'curl -sLO https://github.com/epi052/feroxbuster/releases/latest/download/feroxbuster_amd64.deb.zip && unzip feroxbuster_amd64.deb.zip && sudo dpkg -i feroxbuster_*_amd64.deb && rm feroxbuster*',
            'wafw00f': 'pip3 install wafw00f --break-system-packages',
            'nuclei': 'curl -sSfL https://raw.githubusercontent.com/projectdiscovery/nuclei/main/install.sh | sh -s -- -b /usr/local/bin',
            'katana': 'curl -sSfL https://raw.githubusercontent.com/projectdiscovery/katana/main/install.sh | sh -s -- -b /usr/local/bin',
            'gau': 'wget https://github.com/lc/gau/releases/latest/download/gau_linux_amd64.tar.gz -O /tmp/gau.tar.gz && tar -xzf /tmp/gau.tar.gz -C /tmp && sudo mv /tmp/gau /usr/local/bin/ && rm /tmp/gau*',
            'assetfinder': 'wget https://github.com/tomnomnom/assetfinder/releases/latest/download/assetfinder-linux-amd64.tgz -O /tmp/assetfinder.tgz && tar -xzf /tmp/assetfinder.tgz -C /tmp && sudo mv /tmp/assetfinder /usr/local/bin/ && rm /tmp/assetfinder*',
            'gf': 'go install github.com/tomnomnom/gf@latest && mkdir -p ~/.gf && git clone https://github.com/1ndianl33t/Gf-Patterns ~/.gf || echo "gf patterns already exist"'
        },
        'kali': {
            'subfinder': 'sudo apt-get update && sudo apt-get install -y subfinder || curl -sSfL https://raw.githubusercontent.com/projectdiscovery/subfinder/main/install.sh | sh -s -- -b /usr/local/bin',
            'amass': 'sudo apt-get update && sudo apt-get install -y amass',
            'dnsx': 'curl -sSfL https://raw.githubusercontent.com/projectdiscovery/dnsx/main/install.sh | sh -s -- -b /usr/local/bin',
            'httpx': 'curl -sSfL https://raw.githubusercontent.com/projectdiscovery/httpx/main/install.sh | sh -s -- -b /usr/local/bin',
            'nmap': 'sudo apt-get update && sudo apt-get install -y nmap',
            'naabu': 'curl -sSfL https://raw.githubusercontent.com/projectdiscovery/naabu/main/install.sh | sh -s -- -b /usr/local/bin',
            'feroxbuster': 'sudo apt-get update && sudo apt-get install -y feroxbuster',
            'wafw00f': 'sudo apt-get update && sudo apt-get install -y wafw00f',
            'nuclei': 'sudo apt-get update && sudo apt-get install -y nuclei || curl -sSfL https://raw.githubusercontent.com/projectdiscovery/nuclei/main/install.sh | sh -s -- -b /usr/local/bin',
            'katana': 'curl -sSfL https://raw.githubusercontent.com/projectdiscovery/katana/main/install.sh | sh -s -- -b /usr/local/bin',
            'gau': 'sudo apt-get install -y gau || (wget https://github.com/lc/gau/releases/latest/download/gau_linux_amd64.tar.gz -O /tmp/gau.tar.gz && tar -xzf /tmp/gau.tar.gz -C /tmp && sudo mv /tmp/gau /usr/local/bin/ && rm /tmp/gau*)',
            'assetfinder': 'sudo apt-get install -y assetfinder || (wget https://github.com/tomnomnom/assetfinder/releases/latest/download/assetfinder-linux-amd64.tgz -O /tmp/assetfinder.tgz && tar -xzf /tmp/assetfinder.tgz -C /tmp && sudo mv /tmp/assetfinder /usr/local/bin/ && rm /tmp/assetfinder*)',
            'gf': 'sudo apt-get install -y gf || go install github.com/tomnomnom/gf@latest && mkdir -p ~/.gf && git clone https://github.com/1ndianl33t/Gf-Patterns ~/.gf || echo "gf patterns already exist"'
        },
        'arch': {
            'subfinder': 'yay -S --noconfirm subfinder || curl -sSfL https://raw.githubusercontent.com/projectdiscovery/subfinder/main/install.sh | sh -s -- -b /usr/local/bin',
            'amass': 'yay -S --noconfirm amass',
            'dnsx': 'curl -sSfL https://raw.githubusercontent.com/projectdiscovery/dnsx/main/install.sh | sh -s -- -b /usr/local/bin',
            'httpx': 'curl -sSfL https://raw.githubusercontent.com/projectdiscovery/httpx/main/install.sh | sh -s -- -b /usr/local/bin',
            'nmap': 'sudo pacman -S --noconfirm nmap',
            'naabu': 'curl -sSfL https://raw.githubusercontent.com/projectdiscovery/naabu/main/install.sh | sh -s -- -b /usr/local/bin',
            'feroxbuster': 'yay -S --noconfirm feroxbuster || cargo install feroxbuster',
            'wafw00f': 'pip3 install wafw00f --break-system-packages',
            'nuclei': 'curl -sSfL https://raw.githubusercontent.com/projectdiscovery/nuclei/main/install.sh | sh -s -- -b /usr/local/bin',
            'katana': 'curl -sSfL https://raw.githubusercontent.com/projectdiscovery/katana/main/install.sh | sh -s -- -b /usr/local/bin',
            'gau': 'wget https://github.com/lc/gau/releases/latest/download/gau_linux_amd64.tar.gz -O /tmp/gau.tar.gz && tar -xzf /tmp/gau.tar.gz -C /tmp && sudo mv /tmp/gau /usr/local/bin/ && rm /tmp/gau*',
            'assetfinder': 'wget https://github.com/tomnomnom/assetfinder/releases/latest/download/assetfinder-linux-amd64.tgz -O /tmp/assetfinder.tgz && tar -xzf /tmp/assetfinder.tgz -C /tmp && sudo mv /tmp/assetfinder /usr/local/bin/ && rm /tmp/assetfinder*',
            'gf': 'go install github.com/tomnomnom/gf@latest && mkdir -p ~/.gf && git clone https://github.com/1ndianl33t/Gf-Patterns ~/.gf || echo "gf patterns already exist"'
        },
        'macos': {
            'subfinder': 'brew install subfinder || curl -sSfL https://raw.githubusercontent.com/projectdiscovery/subfinder/main/install.sh | sh -s -- -b /usr/local/bin',
            'amass': 'brew install amass',
            'dnsx': 'curl -sSfL https://raw.githubusercontent.com/projectdiscovery/dnsx/main/install.sh | sh -s -- -b /usr/local/bin',
            'httpx': 'curl -sSfL https://raw.githubusercontent.com/projectdiscovery/httpx/main/install.sh | sh -s -- -b /usr/local/bin',
            'nmap': 'brew install nmap',
            'naabu': 'curl -sSfL https://raw.githubusercontent.com/projectdiscovery/naabu/main/install.sh | sh -s -- -b /usr/local/bin',
            'feroxbuster': 'brew install feroxbuster',
            'wafw00f': 'pip3 install wafw00f',
            'nuclei': 'brew install nuclei || curl -sSfL https://raw.githubusercontent.com/projectdiscovery/nuclei/main/install.sh | sh -s -- -b /usr/local/bin',
            'katana': 'curl -sSfL https://raw.githubusercontent.com/projectdiscovery/katana/main/install.sh | sh -s -- -b /usr/local/bin',
            'gau': 'brew install gau',
            'assetfinder': 'brew install assetfinder',
            'gf': 'brew install gf && mkdir -p ~/.gf && git clone https://github.com/1ndianl33t/Gf-Patterns ~/.gf || echo "gf patterns already exist"'
        }
    }
    
    @staticmethod
    def detect_os():
        """Enhanced OS detection"""
        system = platform.system().lower()
        
        if system == 'linux':
            try:
                with open('/etc/os-release', 'r') as f:
                    content = f.read().lower()
                    if 'kali' in content:
                        return 'kali'
                    elif 'arch' in content or 'manjaro' in content:
                        return 'arch'
                    else:
                        return 'ubuntu'
            except FileNotFoundError:
                return 'ubuntu'
        elif system == 'darwin':
            return 'macos'
        else:
            return 'ubuntu'
    
    @staticmethod
    def install_tool(tool_name, os_type):
        """Install a specific tool with enhanced error handling"""
        commands = ToolInstaller.TOOL_INSTALL_COMMANDS.get(os_type, {})
        if tool_name not in commands:
            print(f"{Fore.RED}[✗] No installation command for {tool_name} on {os_type}")
            return False
        
        cmd = commands[tool_name]
        print(f"{Fore.YELLOW}[+] Installing {tool_name}...")
        print(f"{Fore.CYAN}    Command: {cmd}")
        
        try:
            # Ensure necessary directories exist
            os.makedirs('/tmp', exist_ok=True)
            
            result = subprocess.run(
                cmd, 
                shell=True, 
                capture_output=True, 
                text=True, 
                timeout=600,  # Increased timeout
                env=dict(os.environ, PATH=os.environ['PATH'] + ':/usr/local/bin:/usr/local/go/bin')
            )
            
            if result.returncode == 0:
                print(f"{Fore.GREEN}[✓] {tool_name} installed successfully")
                return True
            else:
                print(f"{Fore.RED}[✗] Failed to install {tool_name}")
                print(f"{Fore.RED}    Error: {result.stderr[:500]}...")
                return False
                
        except subprocess.TimeoutExpired:
            print(f"{Fore.RED}[✗] Installation of {tool_name} timed out")
            return False
        except Exception as e:
            print(f"{Fore.RED}[✗] Error installing {tool_name}: {str(e)}")
            return False
    
    @staticmethod
    def install_missing_tools(missing_tools):
        """Install all missing tools with parallel processing"""
        os_type = ToolInstaller.detect_os()
        print(f"{Fore.CYAN}[+] Detected OS: {os_type}")
        print(f"{Fore.YELLOW}[+] Installing {len(missing_tools)} missing tools...")
        
        # Install tools in parallel for faster installation
        installed_count = 0
        failed_tools = []
        
        # Some tools should be installed sequentially (package managers)
        sequential_tools = ['amass', 'nmap', 'wafw00f']
        parallel_tools = [t for t in missing_tools if t not in sequential_tools]
        sequential_install = [t for t in missing_tools if t in sequential_tools]
        
        # Install sequential tools first
        for tool in sequential_install:
            if ToolInstaller.install_tool(tool, os_type):
                installed_count += 1
            else:
                failed_tools.append(tool)
        
        # Install parallel tools
        if parallel_tools:
            with ThreadPoolExecutor(max_workers=3) as executor:
                future_to_tool = {
                    executor.submit(ToolInstaller.install_tool, tool, os_type): tool 
                    for tool in parallel_tools
                }
                
                for future in as_completed(future_to_tool):
                    tool = future_to_tool[future]
                    try:
                        if future.result():
                            installed_count += 1
                        else:
                            failed_tools.append(tool)
                    except Exception as e:
                        print(f"{Fore.RED}[✗] Error installing {tool}: {e}")
                        failed_tools.append(tool)
        
        # Print installation summary
        print(f"\n{Fore.GREEN}[✓] Installation Summary:")
        print(f"{Fore.GREEN}    Successfully installed: {installed_count}/{len(missing_tools)} tools")
        
        if failed_tools:
            print(f"{Fore.RED}    Failed to install: {', '.join(failed_tools)}")
            print(f"{Fore.YELLOW}    You may need to install these manually:")
            for tool in failed_tools:
                print(f"{Fore.YELLOW}      - {tool}: Check the tool's official documentation")
        
        return len(failed_tools) == 0

class RiskAnalyzer:
    """Enhanced risk analysis with comprehensive patterns"""
    
    HIGH_RISK_PATTERNS = [
        r'admin', r'panel', r'dashboard', r'cpanel', r'phpmyadmin',
        r'wp-admin', r'login', r'portal', r'management', r'control',
        r'backdoor', r'shell', r'webshell', r'backup', r'config',
        r'database', r'db', r'sql', r'api/v\d+', r'swagger',
        r'graphql', r'debug', r'test', r'staging', r'dev',
        r'jenkins', r'gitlab', r'git', r'\.git', r'console'
    ]
    
    MEDIUM_RISK_PATTERNS = [
        r'upload', r'file', r'document', r'pdf', r'img', r'image',
        r'search', r'query', r'redirect', r'proxy', r'api',
        r'webhook', r'callback', r'download', r'export',
        r'user', r'profile', r'account', r'settings'
    ]
    
    SENSITIVE_EXTENSIONS = [
        '.env', '.config', '.json', '.xml', '.yml', '.yaml',
        '.sql', '.db', '.backup', '.bak', '.old', '.tmp',
        '.log', '.conf', '.ini', '.properties'
    ]

    @staticmethod
    def analyze_endpoint_risk(endpoint):
        """Calculate risk score for endpoint"""
        risk_score = 1
        endpoint_lower = endpoint.lower()
        
        # High risk patterns
        for pattern in RiskAnalyzer.HIGH_RISK_PATTERNS:
            if re.search(pattern, endpoint_lower):
                risk_score += 3
        
        # Medium risk patterns
        for pattern in RiskAnalyzer.MEDIUM_RISK_PATTERNS:
            if re.search(pattern, endpoint_lower):
                risk_score += 2
        
        # Sensitive extensions
        for ext in RiskAnalyzer.SENSITIVE_EXTENSIONS:
            if endpoint_lower.endswith(ext):
                risk_score += 2
        
        # Parameters indicate potential injection points
        if '?' in endpoint:
            risk_score += 1
        
        # Multiple parameters increase risk
        if endpoint.count('=') > 2:
            risk_score += 1
        
        return min(risk_score, 10)
    
    @staticmethod
    def analyze_endpoint_risk_detailed(endpoint):
        """Detailed endpoint analysis for fallback"""
        risk_score = RiskAnalyzer.analyze_endpoint_risk(endpoint)
        
        explanations = []
        endpoint_lower = endpoint.lower()
        
        if any(re.search(pattern, endpoint_lower) for pattern in RiskAnalyzer.HIGH_RISK_PATTERNS):
            explanations.append("Contains high-risk keywords (admin/debug/config)")
        if any(re.search(pattern, endpoint_lower) for pattern in RiskAnalyzer.MEDIUM_RISK_PATTERNS):
            explanations.append("Contains medium-risk patterns (upload/api/user)")
        if any(endpoint_lower.endswith(ext) for ext in RiskAnalyzer.SENSITIVE_EXTENSIONS):
            explanations.append("Sensitive file extension detected")
        if '?' in endpoint:
            explanations.append("Contains parameters - potential injection point")
        if endpoint.count('=') > 2:
            explanations.append("Multiple parameters - increased attack surface")
        
        return {
            'endpoint': endpoint,
            'risk_score': risk_score,
            'ai_explanation': '; '.join(explanations) if explanations else "Standard risk assessment",
            'testing_approach': "Test for parameter injection, authentication bypass, and information disclosure",
            'analysis_type': 'pattern_based'
        }

    @staticmethod
    def analyze_js_endpoint(js_content):
        """Analyze JavaScript content for interesting patterns"""
        interesting_patterns = [
            (r'api[/.]v\d+[/.][\w/]+', 'API Endpoint'),
            (r'/admin[/\w]*', 'Admin Path'),
            (r'/api[/\w]*', 'API Path'),
            (r'\.php\?[\w=&]+', 'PHP with Parameters'),
            (r'token["\s]*[:=]["\s]*[\w-]+', 'Authentication Token'),
            (r'secret["\s]*[:=]["\s]*[\w-]+', 'Secret Key'),
            (r'password["\s]*[:=]["\s]*[\w-]+', 'Password'),
            (r'https?://[^\s"\'<>)]+', 'External URL'),
        ]
        
        findings = []
        for pattern, description in interesting_patterns:
            matches = re.findall(pattern, js_content, re.IGNORECASE)
            for match in matches:
                findings.append({
                    'type': description,
                    'match': match,
                    'risk_score': RiskAnalyzer.analyze_endpoint_risk(match)
                })
        
        return findings

class EmailNotifier:
    """Simplified Email notification system"""
    
    def __init__(self, config):
        self.email_config = config.get('email', {})
    
    def send_notification(self, findings_summary, detailed_report):
        """Send email notification with findings"""
        if not self._is_configured():
            return False
        
        try:
            msg = MIMEMultipart()
            msg['From'] = self.email_config['sender_email']
            msg['To'] = self.email_config['recipient_email']
            msg['Subject'] = f"🤖 Gemini AI Recon Complete: {findings_summary['domain']}"
            
            body = self._create_email_body(findings_summary, detailed_report)
            msg.attach(MIMEText(body, 'plain'))
            
            with smtplib.SMTP(self.email_config['smtp_server'], 587) as server:
                server.starttls()
                server.login(self.email_config['sender_email'], self.email_config['sender_password'])
                server.send_message(msg)
            
            return True
            
        except Exception as e:
            print(f"{Fore.YELLOW}[!] Email notification failed: {e}")
            return False
    
    def _is_configured(self):
        """Check if email is properly configured"""
        required_fields = ['smtp_server', 'sender_email', 'sender_password', 'recipient_email']
        return all(self.email_config.get(field) for field in required_fields)
    
    def _create_email_body(self, findings_summary, detailed_report):
        """Create email body content"""
        return f"""
Gemini AI-Enhanced Bug Bounty Reconnaissance Completed!

Domain: {findings_summary['domain']}
Scan Completed: {findings_summary['completion_time']}
AI Engine: {'Gemini Pro ✓' if findings_summary['gemini_enabled'] else 'Pattern-based (Gemini not configured)'}

📊 RESULTS SUMMARY:
├── Live Targets: {findings_summary['live_targets']}
├── Total Endpoints: {findings_summary['total_endpoints']}
├── AI-Analyzed: {findings_summary.get('ai_analysis_count', 'N/A')}
├── High Risk Findings: {findings_summary['high_risk']}
└── Vulnerabilities: {findings_summary['vulnerabilities']}

🔥 TOP HIGH-RISK FINDINGS:
{detailed_report}

The reconnaissance has been completed successfully. Check the detailed results in your output directory.

Happy Bug Hunting! 🎯
        """

class FileManager:
    """Centralized file management for better organization"""
    
    def __init__(self, domain):
        self.domain = domain
        self.base_dir = Path(f"./recon/{domain}")
        self.base_dir.mkdir(parents=True, exist_ok=True)
        
        # Define all file paths
        self.files = {
            'subfinder': self.base_dir / "subfinder.txt",
            'amass': self.base_dir / "amass.txt",
            'amass_domains': self.base_dir / "amass_domains.txt",
            'dnsx': self.base_dir / "dnsx.txt",
            'final_subdomains': self.base_dir / "final_subdomains.txt",
            'targets': self.base_dir / "targets.txt",
            'gau': self.base_dir / "gau.txt",
            'katana': self.base_dir / "katana.txt",
            'nuclei_results': self.base_dir / "nuclei_results.txt",
            'prioritized_findings': self.base_dir / "prioritized_findings.json",
            'js_analysis': self.base_dir / "js_analysis.json",
            'org_assets': self.base_dir / "org_assets.txt",
            'gemini_analysis': self.base_dir / "gemini_analysis.json",
            'summary': self.base_dir / "summary.txt",
            'clean_targets': self.base_dir / "clean_targets.txt",
            'waf_results': self.base_dir / "waf_results.txt",
            'combined_urls': self.base_dir / "combined_urls.txt"
        }
    
    def get_file(self, file_key):
        """Get file path by key"""
        return self.files.get(file_key)
    
    def file_exists(self, file_key):
        """Check if file exists"""
        file_path = self.get_file(file_key)
        return file_path and file_path.exists()
    
    def read_lines(self, file_key):
        """Read lines from file"""
        file_path = self.get_file(file_key)
        if file_path and file_path.exists():
            with open(file_path, 'r') as f:
                return [line.strip() for line in f if line.strip()]
        return []
    
    def write_lines(self, file_key, lines):
        """Write lines to file"""
        file_path = self.get_file(file_key)
        if file_path:
            with open(file_path, 'w') as f:
                for line in lines:
                    f.write(f"{line}\n")
    
    def count_lines(self, file_key):
        """Count lines in file"""
        return len(self.read_lines(file_key))

class CommandRunner:
    """Centralized command execution with better error handling"""
    
    @staticmethod
    def run(cmd, output_file=None, description="", timeout=1800):
        """Execute command with enhanced error handling"""
        if description:
            print(f"{Fore.BLUE}[+] {description}")
        print(f"{Fore.CYAN}    Command: {cmd}")
        
        try:
            result = subprocess.run(
                cmd, 
                shell=True, 
                capture_output=True, 
                text=True, 
                timeout=timeout,
                env=dict(os.environ, PATH=os.environ['PATH'] + ':/usr/local/bin')
            )
            
            if result.returncode == 0:
                if output_file and result.stdout:
                    with open(output_file, 'w') as f:
                        f.write(result.stdout)
                print(f"{Fore.GREEN}[✓] Command completed successfully")
                return True
            else:
                print(f"{Fore.RED}[✗] Command failed with return code {result.returncode}")
                if result.stderr:
                    print(f"{Fore.RED}    Error: {result.stderr[:200]}...")
                return False
                
        except subprocess.TimeoutExpired:
            print(f"{Fore.YELLOW}[!] Command timed out after {timeout//60} minutes")
            return False
        except Exception as e:
            print(f"{Fore.RED}[✗] Error running command: {str(e)}")
            return False

class ReconFramework:
    """Main reconnaissance framework - refactored for better organization"""
    
    def __init__(self, domain, batch_mode=False, threads=50, config_file=None):
        self.domain = domain
        self.batch_mode = batch_mode
        self.threads = threads
        
        # Initialize components
        self.config = self._load_config(config_file)
        self.file_manager = FileManager(domain)
        self.gemini_analyzer = GeminiAnalyzer(self.config.get('gemini_api_key'))
        self.risk_analyzer = RiskAnalyzer()
        self.email_notifier = EmailNotifier(self.config)
        
        # Findings storage
        self.high_risk_findings = []
        self.all_findings = []
        self.ai_analysis_count = 0

    def _load_config(self, config_file):
        """Load configuration from file"""
        default_config = {
            'email': {},
            'shodan_api_key': None,
            'gemini_api_key': None
        }
        
        if config_file and Path(config_file).exists():
            try:
                with open(config_file, 'r') as f:
                    user_config = json.load(f)
                default_config.update(user_config)
            except Exception as e:
                print(f"{Fore.YELLOW}[!] Error loading config: {e}")
        
        return default_config

    def _print_status(self, message, status="INFO"):
        """Print colored status messages"""
        colors = {
            "INFO": Fore.BLUE,
            "SUCCESS": Fore.GREEN,
            "WARNING": Fore.YELLOW,
            "ERROR": Fore.RED,
            "QUESTION": Fore.CYAN,
            "HIGH_RISK": Fore.RED + Style.BRIGHT,
            "AI": Fore.MAGENTA + Style.BRIGHT
        }
        symbols = {
            "INFO": "[+]",
            "SUCCESS": "[✓]",
            "WARNING": "[!]",
            "ERROR": "[✗]",
            "QUESTION": "[?]",
            "HIGH_RISK": "[🔥]",
            "AI": "[🤖]"
        }
        print(f"{colors[status]}{symbols[status]} {message}")

    def _get_user_input(self, prompt, default=""):
        """Get user input with batch mode support"""
        if self.batch_mode:
            return default
        return input(f"{Fore.CYAN}[?] {prompt} [{default}]: ").strip() or default

    def check_dependencies(self):
        """Check and install missing tools"""
        self._print_status("Checking required tools...")
        
        required_tools = [
            "subfinder", "amass", "dnsx", "httpx", "nmap", "naabu", 
            "feroxbuster", "wafw00f", "nuclei", "katana", "gf", "gau"
        ]
        
        missing_tools = [tool for tool in required_tools if not shutil.which(tool)]
        
        if missing_tools:
            self._print_status(f"Missing required tools: {', '.join(missing_tools)}", "ERROR")
            
            install_choice = self._get_user_input(
                "Install missing tools automatically? (y/n)", "y"
            )
            
            if install_choice.lower() == 'y':
                if ToolInstaller.install_missing_tools(missing_tools):
                    self._print_status("Tools installed! Please restart the script.", "SUCCESS")
                    sys.exit(0)
                else:
                    self._print_status("Some tools failed to install. Check manually.", "ERROR")
                    sys.exit(1)
            else:
                self._print_status("Cannot proceed without required tools", "ERROR")
                sys.exit(1)
        
        self._print_status("All required tools found", "SUCCESS")
        
        # Check Gemini AI
        if self.gemini_analyzer.model:
            self._print_status("Gemini AI configured and ready", "AI")
        else:
            self._print_status("Gemini AI not configured - using pattern-based analysis", "WARNING")

    def subdomain_enumeration(self):
        """Enhanced subdomain enumeration phase"""
        self._print_status("=== SUBDOMAIN ENUMERATION ===", "INFO")
        
        # Subfinder
        subfinder_threads = self._get_user_input("Subfinder threads", "50")
        subfinder_cmd = f"subfinder -d {self.domain} -all -t {subfinder_threads} -silent -o {self.file_manager.get_file('subfinder')}"
        CommandRunner.run(subfinder_cmd, description="Running Subfinder")
        
        # Amass - Fixed version
        amass_timeout = self._get_user_input("Amass timeout (minutes)", "15")
        amass_cmd = f"timeout {amass_timeout}m amass enum -d {self.domain} -o {self.file_manager.get_file('amass')}"
        
        if CommandRunner.run(amass_cmd, description="Running Amass"):
            # Use Python-based filtering instead of grep
            self._filter_amass_results_python()
        
        # DNSX bruteforcing
        use_dnsx = self._get_user_input("Use DNSX for subdomain bruteforcing? (y/n)", "y")
        if use_dnsx.lower() == 'y':
            wordlist_path = self._get_user_input(
                "DNSX wordlist path", 
                "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
            )
            dnsx_threads = self._get_user_input("DNSX threads", "100")
            
            if os.path.exists(wordlist_path):
                dnsx_cmd = f"dnsx -d {self.domain} -w {wordlist_path} -t {dnsx_threads} -silent -o {self.file_manager.get_file('dnsx')}"
                CommandRunner.run(dnsx_cmd, description="Running DNSX bruteforce")
        
        self._combine_subdomains()
        self._check_live_hosts()

    def _filter_amass_results_python(self):
        """Python-based filtering of Amass results (more reliable than grep)"""
        try:
            amass_file = self.file_manager.get_file('amass')
            amass_domains_file = self.file_manager.get_file('amass_domains')
            
            if not amass_file.exists():
                return
            
            valid_domains = []
            # Improved domain pattern that handles various subdomain formats
            domain_pattern = re.compile(
                r'([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+' + 
                re.escape(self.domain) + r'(?=\s|$|[^a-zA-Z0-9\-\.])',
                re.IGNORECASE
            )
            
            with open(amass_file, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    
                    # Extract domain from line (Amass output can have various formats)
                    # Try direct domain extraction first
                    if line.endswith(f'.{self.domain}') or line == self.domain:
                        if line not in valid_domains:
                            valid_domains.append(line)
                    else:
                        # Use regex pattern for more complex cases
                        matches = domain_pattern.findall(line)
                        for match in matches:
                            if isinstance(match, tuple):
                                domain_found = ''.join(match) + self.domain
                            else:
                                domain_found = match
                            
                            # Additional validation
                            if (domain_found.endswith(f'.{self.domain}') or domain_found == self.domain) and \
                               domain_found not in valid_domains:
                                valid_domains.append(domain_found)
            
            # Write filtered results
            with open(amass_domains_file, 'w') as f:
                for domain in sorted(set(valid_domains)):
                    f.write(f"{domain}\n")
            
            self._print_status(f"Filtered {len(valid_domains)} valid domains from Amass results", "SUCCESS")
            
        except Exception as e:
            self._print_status(f"Error filtering Amass results: {e}", "WARNING")
            # Fallback to original results if filtering fails
            try:
                shutil.copy2(amass_file, amass_domains_file)
            except Exception:
                pass

    def _combine_subdomains(self):
        """Combine all subdomain results"""
        self._print_status("Combining subdomain results...")
        
        all_subdomains = set()
        
        # Collect from all sources
        for file_key in ['subfinder', 'amass_domains', 'dnsx', 'org_assets']:
            subdomains = self.file_manager.read_lines(file_key)
            for subdomain in subdomains:
                if subdomain and '.' in subdomain:
                    all_subdomains.add(subdomain)
        
        # Write combined results
        self.file_manager.write_lines('final_subdomains', sorted(all_subdomains))
        self._print_status(f"Found {len(all_subdomains)} unique subdomains", "SUCCESS")

    def _check_live_hosts(self):
        """Check for live hosts using httpx"""
        self._print_status("=== LIVE HOST DETECTION ===", "INFO")
        
        httpx_threads = self._get_user_input("HTTPx threads", "100")
        httpx_timeout = self._get_user_input("HTTPx timeout (seconds)", "10")
        
        httpx_cmd = f"cat {self.file_manager.get_file('final_subdomains')} | httpx -threads {httpx_threads} -timeout {httpx_timeout} -status-code -location -title -tech-detect -silent -o {self.file_manager.get_file('targets')}"
        
        if CommandRunner.run(httpx_cmd, description="Running HTTPx"):
            live_count = self.file_manager.count_lines('targets')
            self._print_status(f"Found {live_count} live targets", "SUCCESS")

    def endpoint_discovery(self):
        """Enhanced endpoint discovery using multiple sources"""
        self._print_status("=== ENDPOINT DISCOVERY ===", "INFO")
        
        # GAU historical endpoints
        gau_providers = self._get_user_input("GAU providers", "wayback,commoncrawl")
        gau_threads = self._get_user_input("GAU threads", "10")
        gau_cmd = f"gau {self.domain} --providers {gau_providers} --threads {gau_threads} --o {self.file_manager.get_file('gau')}"
        CommandRunner.run(gau_cmd, description="Running GAU")
        
        # Katana web crawling
        if self.file_manager.file_exists('targets'):
            targets = self.file_manager.read_lines('targets')
            if targets:
                first_target = targets[0].split()[0]
                katana_depth = self._get_user_input("Katana crawling depth", "3")
                katana_cmd = f"katana -jc -u {first_target} -d {katana_depth} -aff -o {self.file_manager.get_file('katana')}"
                CommandRunner.run(katana_cmd, description=f"Running Katana on {first_target}")

    def gemini_enhanced_analysis(self):
        """Gemini AI-powered endpoint analysis"""
        self._print_status("=== GEMINI AI ANALYSIS ===", "AI")
        
        # Collect all endpoints
        all_endpoints = []
        for file_key in ['gau', 'katana']:
            all_endpoints.extend(self.file_manager.read_lines(file_key))
        
        if not all_endpoints:
            self._print_status("No endpoints found for analysis", "WARNING")
            return
        
        self._print_status(f"Analyzing {len(all_endpoints)} endpoints...")
        
        # Limit AI analysis to prevent API overuse
        max_ai_analysis = int(self._get_user_input("Max endpoints for AI analysis", "50"))
        
        # Prioritize endpoints by risk score for AI analysis
        high_priority_endpoints = sorted(
            all_endpoints, 
            key=lambda x: self.risk_analyzer.analyze_endpoint_risk(x), 
            reverse=True
        )[:max_ai_analysis]
        
        # Analyze with AI (limited concurrency)
        ai_analyzed_endpoints = []
        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = [
                executor.submit(self._analyze_endpoint_with_gemini, endpoint) 
                for endpoint in high_priority_endpoints
            ]
            
            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        ai_analyzed_endpoints.append(result)
                        self.ai_analysis_count += 1
                        
                        if result['risk_score'] >= 7:
                            self.high_risk_findings.append(result)
                            self._print_status(
                                f"AI HIGH RISK: {result['endpoint']} (Score: {result['risk_score']}) - {result['ai_explanation'][:80]}...", 
                                "HIGH_RISK"
                            )
                        
                        time.sleep(0.5)  # Rate limiting
                        
                except Exception as e:
                    self._print_status(f"AI analysis error: {e}", "ERROR")
        
        # Analyze remaining endpoints with pattern matching
        remaining_endpoints = [
            ep for ep in all_endpoints 
            if ep not in [r['endpoint'] for r in ai_analyzed_endpoints]
        ]
        
        for endpoint in remaining_endpoints:
            finding = self.risk_analyzer.analyze_endpoint_risk_detailed(endpoint)
            finding['timestamp'] = time.time()
            self.all_findings.append(finding)
            
            if finding['risk_score'] >= 7:
                self.high_risk_findings.append(finding)
                self._print_status(f"HIGH RISK: {endpoint} (Score: {finding['risk_score']})", "HIGH_RISK")
        
        # Add AI findings to all findings
        self.all_findings.extend(ai_analyzed_endpoints)
        
        # Save analysis results
        self._save_analysis_results(len(all_endpoints), ai_analyzed_endpoints)
        
        self._print_status(f"Analysis complete! AI analyzed: {len(ai_analyzed_endpoints)}", "AI")
        self._print_status(f"Found {len(self.high_risk_findings)} high-risk endpoints", "SUCCESS")

    def _analyze_endpoint_with_gemini(self, endpoint):
        """Analyze individual endpoint with Gemini AI"""
        try:
            return self.gemini_analyzer.analyze_endpoint_with_ai(endpoint)
        except Exception as e:
            self._print_status(f"Gemini analysis failed for {endpoint}: {e}", "WARNING")
            return None

    def _save_analysis_results(self, total_endpoints, ai_analyzed_endpoints):
        """Save analysis results to file"""
        analysis_data = {
            'total_endpoints': total_endpoints,
            'ai_analyzed_count': len(ai_analyzed_endpoints),
            'high_risk_findings': self.high_risk_findings,
            'analysis_timestamp': time.time(),
            'gemini_model_used': self.gemini_analyzer.model is not None
        }
        
        with open(self.file_manager.get_file('gemini_analysis'), 'w') as f:
            json.dump(analysis_data, f, indent=2)

    def vulnerability_scanning(self):
        """Enhanced vulnerability scanning"""
        self._print_status("=== VULNERABILITY SCANNING ===", "INFO")
        
        if not self.file_manager.file_exists('targets'):
            self._print_status("No targets file found. Skipping vulnerability scanning.", "WARNING")
            return
        
        nuclei_threads = self._get_user_input("Nuclei threads", "50")
        nuclei_templates = self._get_user_input("Nuclei template tags", "cve,oast,default-logins")
        
        nuclei_cmd = f"nuclei -l {self.file_manager.get_file('targets')} -c {nuclei_threads}"
        if nuclei_templates:
            nuclei_cmd += f" -tags {nuclei_templates}"
        nuclei_cmd += f" -o {self.file_manager.get_file('nuclei_results')}"
        
        CommandRunner.run(nuclei_cmd, description="Running Nuclei vulnerability scan")

    def pattern_matching(self):
        """Enhanced pattern matching with GF"""
        self._print_status("=== PATTERN MATCHING ===", "INFO")
        
        # Combine all URLs
        all_urls = []
        for file_key in ['gau', 'katana']:
            all_urls.extend(self.file_manager.read_lines(file_key))
        
        if not all_urls:
            self._print_status("No URLs found for pattern matching", "WARNING")
            return
        
        # Write combined URLs
        self.file_manager.write_lines('combined_urls', all_urls)
        
        # Run GF patterns
        patterns = ["xss", "sqli", "lfi", "ssti", "idor", "redirect", "rce", "ssrf", "debug", "admin"]
        
        for pattern in patterns:
            output_file = self.file_manager.base_dir / f"gf_{pattern}.txt"
            cmd = f"cat {self.file_manager.get_file('combined_urls')} | gf {pattern} > {output_file}"
            CommandRunner.run(cmd, description=f"GF pattern matching: {pattern}")
            
            if output_file.exists():
                with open(output_file, 'r') as f:
                    count = len([line for line in f if line.strip()])
                if count > 0:
                    self._print_status(f"Found {count} {pattern} patterns", "SUCCESS")

    def generate_summary(self):
        """Generate comprehensive summary"""
        self._print_status("=== GENERATING SUMMARY ===", "AI")
        
        # Collect statistics
        stats = {
            'domain': self.domain,
            'subdomains': self.file_manager.count_lines('final_subdomains'),
            'live_targets': self.file_manager.count_lines('targets'),
            'total_endpoints': len(self.all_findings),
            'ai_analysis_count': self.ai_analysis_count,
            'high_risk': len(self.high_risk_findings),
            'vulnerabilities': self.file_manager.count_lines('nuclei_results'),
            'completion_time': time.strftime('%Y-%m-%d %H:%M:%S'),
            'gemini_enabled': self.gemini_analyzer.model is not None
        }
        
        # Generate summary report
        summary_content = self._create_summary_content(stats)
        
        with open(self.file_manager.get_file('summary'), 'w') as f:
            f.write(summary_content)
        
        self._print_status(f"Summary saved to {self.file_manager.get_file('summary')}", "SUCCESS")
        return stats

    def _create_summary_content(self, stats):
        """Create detailed summary content"""
        content = f"""🤖 GEMINI AI-ENHANCED BUG BOUNTY RECONNAISSANCE SUMMARY
{'=' * 60}

Domain: {stats['domain'].upper()}
Scan Date: {stats['completion_time']}
AI Engine: {'Gemini Pro ✓' if stats['gemini_enabled'] else 'Pattern-based (Gemini not configured)'}

📊 STATISTICS:
├── Total Subdomains: {stats['subdomains']}
├── Live Targets: {stats['live_targets']}
├── Total Endpoints: {stats['total_endpoints']}
├── AI-Analyzed Endpoints: {stats['ai_analysis_count']}
├── High Risk Findings: {stats['high_risk']}
└── Vulnerabilities: {stats['vulnerabilities']}

"""

        if self.high_risk_findings:
            content += "🔥 TOP HIGH-RISK FINDINGS:\n"
            for i, finding in enumerate(self.high_risk_findings[:10], 1):
                analysis_type = "🤖 AI" if finding.get('analysis_type') == 'gemini_ai' else "📊 Pattern"
                explanation = finding.get('ai_explanation', 'Standard risk assessment')[:80]
                content += f"{i:2d}. [{analysis_type}] {finding['endpoint']} (Risk: {finding['risk_score']}/10)\n"
                content += f"     └─ {explanation}{'...' if len(explanation) == 80 else ''}\n"
            content += "\n"
        
        if stats['ai_analysis_count'] > 0:
            ai_high_risk = [f for f in self.high_risk_findings if f.get('analysis_type') == 'gemini_ai']
            content += f"""🤖 GEMINI AI INSIGHTS:
├── Endpoints analyzed by AI: {stats['ai_analysis_count']}
├── AI-identified high-risk: {len(ai_high_risk)}
└── AI recommendations available in detailed analysis

"""
        
        content += f"📁 All results saved in: {self.file_manager.base_dir.resolve()}\n"
        return content

    def send_notifications(self, findings_summary):
        """Send email notifications"""
        self._print_status("=== SENDING NOTIFICATIONS ===", "INFO")
        
        # Create detailed report for email
        detailed_report = ""
        if self.high_risk_findings:
            detailed_report = "\n".join([
                f"• [{('🤖 AI' if finding.get('analysis_type') == 'gemini_ai' else '📊 Pattern')}] {finding['endpoint']} (Risk: {finding['risk_score']}/10)"
                for finding in self.high_risk_findings[:5]
            ])
        
        if self.email_notifier.send_notification(findings_summary, detailed_report):
            self._print_status("Email notification sent successfully", "SUCCESS")
        else:
            self._print_status("Email notification not configured or failed", "WARNING")

    def run_full_recon(self):
        """Execute complete reconnaissance workflow"""
        self._print_status(f"Starting Gemini AI-enhanced reconnaissance for {self.domain}", "AI")
        
        try:
            # Phase 1: Enumeration
            self.subdomain_enumeration()
            
            # Phase 2: Discovery
            self.endpoint_discovery()
            
            # Phase 3: Analysis
            self.gemini_enhanced_analysis()
            
            # Phase 4: Vulnerability Scanning
            self.vulnerability_scanning()
            
            # Phase 5: Pattern Matching
            self.pattern_matching()
            
            # Phase 6: Reporting
            findings_summary = self.generate_summary()
            self.send_notifications(findings_summary)
            
            self._print_final_summary(findings_summary)
            
        except KeyboardInterrupt:
            self._print_status("Reconnaissance interrupted by user", "WARNING")
            sys.exit(1)
        except Exception as e:
            self._print_status(f"Error during reconnaissance: {str(e)}", "ERROR")
            sys.exit(1)

    def _print_final_summary(self, findings_summary):
        """Print final summary to console"""
        self._print_status("=== RECONNAISSANCE COMPLETE ===", "SUCCESS")
        
        print(f"{Fore.CYAN}Domain: {Fore.WHITE}{findings_summary['domain']}")
        print(f"{Fore.CYAN}Live Targets: {Fore.WHITE}{findings_summary['live_targets']}")
        print(f"{Fore.CYAN}High Risk Findings: {Fore.RED}{findings_summary['high_risk']}")
        print(f"{Fore.MAGENTA}AI-Analyzed Endpoints: {Fore.WHITE}{findings_summary['ai_analysis_count']}")
        print(f"{Fore.CYAN}Total Vulnerabilities: {Fore.YELLOW}{findings_summary['vulnerabilities']}")
        print(f"{Fore.CYAN}Gemini AI: {Fore.GREEN if findings_summary['gemini_enabled'] else Fore.RED}{findings_summary['gemini_enabled']}")
        print(f"{Fore.CYAN}Results saved in: {Fore.WHITE}{self.file_manager.base_dir.resolve()}")
        
        if findings_summary['high_risk'] > 0:
            self._print_status("🔥 HIGH PRIORITY ITEMS REQUIRE IMMEDIATE ATTENTION!", "HIGH_RISK")

def create_sample_config():
    """Create sample configuration file"""
    sample_config = {
        "email": {
            "smtp_server": "smtp.gmail.com",
            "sender_email": "your-email@gmail.com",
            "sender_password": "your-app-password",
            "recipient_email": "recipient@gmail.com"
        },
        "shodan_api_key": "your-shodan-api-key",
        "gemini_api_key": "your-gemini-api-key"
    }
    
    with open("config.json.sample", 'w') as f:
        json.dump(sample_config, f, indent=4)
    
    print(f"{Fore.GREEN}[✓] Sample configuration created: config.json.sample")
    print(f"{Fore.YELLOW}[!] Copy to config.json and update with your credentials")
    print(f"{Fore.CYAN}[+] Get Gemini API key from: https://makersuite.google.com/app/apikey")

def install_python_dependencies():
    """Install required Python packages"""
    required_packages = [
        "google-generativeai",
        "colorama", 
        "requests"
    ]
    
    print(f"{Fore.CYAN}[+] Checking Python dependencies...")
    
    missing_packages = []
    for package in required_packages:
        try:
            __import__(package.replace('-', '_'))
        except ImportError:
            missing_packages.append(package)
    
    if missing_packages:
        print(f"{Fore.YELLOW}[+] Installing missing packages: {', '.join(missing_packages)}")
        try:
            subprocess.check_call([
                sys.executable, "-m", "pip", "install", 
                "--break-system-packages"
            ] + missing_packages)
            print(f"{Fore.GREEN}[✓] Python dependencies installed")
            return True
        except subprocess.CalledProcessError:
            print(f"{Fore.RED}[✗] Failed to install Python dependencies")
            print(f"{Fore.YELLOW}[!] Please run: pip install {' '.join(missing_packages)}")
            return False
    
    print(f"{Fore.GREEN}[✓] All Python dependencies satisfied")
    return True

def main():
    """Main entry point"""
    print(HEADER)
    
    parser = argparse.ArgumentParser(
        description="Gemini AI-Enhanced Bug Bounty Reconnaissance Framework v4.1"
    )
    parser.add_argument("domain", nargs='?', help="Target domain for reconnaissance")
    parser.add_argument("--batch", action="store_true", help="Run in batch mode (no interaction)")
    parser.add_argument("--threads", type=int, default=50, help="Default number of threads")
    parser.add_argument("--config", type=str, help="Path to configuration file")
    parser.add_argument("--create-config", action="store_true", help="Create sample config file")
    parser.add_argument("--install-deps", action="store_true", help="Install Python dependencies")
    
    args = parser.parse_args()
    
    if args.install_deps:
        install_python_dependencies()
        return
    
    if args.create_config:
        create_sample_config()
        return
    
    if not args.domain:
        print(f"{Fore.RED}[!] Please provide a domain name")
        print(f"{Fore.CYAN}Usage: python3 {sys.argv[0]} example.com [options]")
        print(f"{Fore.CYAN}Options:")
        print(f"{Fore.CYAN}  --create-config  Generate sample configuration")
        print(f"{Fore.CYAN}  --install-deps   Install Python dependencies")
        print(f"{Fore.CYAN}  --batch          Run without user interaction")
        sys.exit(1)
    
    # Install dependencies if needed
    if not install_python_dependencies():
        print(f"{Fore.RED}[!] Please install Python dependencies and try again")
        sys.exit(1)
    
    # Initialize and run framework
    recon = ReconFramework(args.domain, args.batch, args.threads, args.config)
    recon.check_dependencies()
    recon.run_full_recon()

if __name__ == "__main__":
    main()
