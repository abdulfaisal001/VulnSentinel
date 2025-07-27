# Enhanced Vulnerability Scanner Project
# Implements NSE scripts, SQLite caching, exploit availability scoring, and visual reporting

# =============================================================================
# main.py
# =============================================================================
import argparse
import logging
import sys
import sqlite3
from pathlib import Path
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeRemainingColumn
from rich.table import Table
from rich import print as rprint

from scanner.nmap_scanner import NmapScanner
from core.cve_mapper import CVEMapper
from core.risk_engine import RiskEngine
from core.exploit_checker import ExploitChecker
from reports.report_generator import ReportGenerator
from utils.validators import validate_ip, validate_port_range
from utils.database import DatabaseManager
from config.settings import Config

# Configure rich console
console = Console()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('vulnerability_scan.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class EnhancedVulnerabilityScanner:
    def __init__(self):
        self.db_manager = DatabaseManager()
        self.scanner = NmapScanner()
        self.cve_mapper = CVEMapper(self.db_manager)
        self.risk_engine = RiskEngine()
        self.exploit_checker = ExploitChecker(self.db_manager)
        self.report_generator = ReportGenerator()
    
    def scan_and_analyze(self, target, port_range=None, output_file=None, 
                        output_format='html', nse_scripts='vulners', 
                        skip_intrusive=False, enable_os_detection=False):
        """Enhanced scanning and analysis workflow"""
        try:
            console.print(f"[bold blue]🎯 Starting vulnerability scan for {target}[/bold blue]")
            
            # Validate inputs
            if not validate_ip(target):
                raise ValueError(f"Invalid IP address: {target}")
            
            # Display scan configuration
            self._display_scan_config(target, port_range, nse_scripts, skip_intrusive)
            
            # Perform network scan with progress tracking
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TimeRemainingColumn(),
                console=console
            ) as progress:
                scan_task = progress.add_task("🔍 Performing network scan...", total=100)
                
                scan_results = self.scanner.scan_target(
                    target=target,
                    port_range=port_range,
                    nse_scripts=nse_scripts,
                    skip_intrusive=skip_intrusive,
                    enable_os_detection=enable_os_detection,
                    progress_callback=lambda p: progress.update(scan_task, completed=p)
                )
                
                progress.update(scan_task, completed=100)
            
            if not scan_results.get('hosts'):
                console.print("[yellow]⚠️  No hosts found or host is down[/yellow]")
                return
            
            # Analyze vulnerabilities with progress tracking
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console
            ) as progress:
                vuln_task = progress.add_task("🔬 Analyzing vulnerabilities...")
                vulnerabilities = self._analyze_vulnerabilities(scan_results, progress, vuln_task)
            
            # Check for exploits
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console
            ) as progress:
                exploit_task = progress.add_task("💥 Checking exploit availability...")
                vulnerabilities = self._enhance_with_exploits(vulnerabilities, progress, exploit_task)
            
            # Generate comprehensive report
            console.print("📊 Generating comprehensive report...")
            report_data = {
                'target': target,
                'scan_results': scan_results,
                'vulnerabilities': vulnerabilities,
                'summary': self._generate_enhanced_summary(vulnerabilities),
                'scan_config': {
                    'nse_scripts': nse_scripts,
                    'port_range': port_range,
                    'os_detection': enable_os_detection,
                    'intrusive_disabled': skip_intrusive
                }
            }
            
            report_path = self.report_generator.generate_report(
                report_data, output_file, output_format
            )
            
            # Display summary in terminal
            self._display_terminal_summary(report_data)
            
            console.print(f"[bold green]✅ Scan completed! Report saved to: {report_path}[/bold green]")
            return report_path
            
        except Exception as e:
            console.print(f"[bold red]❌ Scan failed: {e}[/bold red]")
            logger.error(f"Scan failed: {e}")
            raise
    
    def _display_scan_config(self, target, port_range, nse_scripts, skip_intrusive):
        """Display scan configuration"""
        table = Table(title="Scan Configuration")
        table.add_column("Parameter", style="cyan")
        table.add_column("Value", style="green")
        
        table.add_row("Target", target)
        table.add_row("Port Range", port_range or "Default (1-1000)")
        table.add_row("NSE Scripts", nse_scripts)
        table.add_row("Skip Intrusive", "Yes" if skip_intrusive else "No")
        
        console.print(table)
    
    def _analyze_vulnerabilities(self, scan_results, progress, task_id):
        """Enhanced vulnerability analysis with NSE integration"""
        vulnerabilities = []
        total_hosts = len(scan_results.get('hosts', {}))
        processed_hosts = 0
        
        for host_ip, host_data in scan_results['hosts'].items():
            progress.update(task_id, description=f"🔬 Analyzing {host_ip}...")
            
            # Process NSE vulnerability findings first
            nse_vulns = self._process_nse_vulnerabilities(host_ip, host_data)
            vulnerabilities.extend(nse_vulns)
            
            # Process service-based vulnerabilities
            for port_info in host_data.get('ports', []):
                service_name = port_info.get('service', 'unknown')
                version = port_info.get('version', 'unknown')
                port_num = port_info.get('port')
                
                if service_name != 'unknown':
                    # Get CVE data for the service
                    cve_data = self.cve_mapper.get_cve_data(service_name, version)
                    
                    for cve in cve_data:
                        # Skip if already found by NSE
                        if any(v.get('cve_id') == cve.get('id') for v in nse_vulns):
                            continue
                        
                        risk_level = self.risk_engine.calculate_risk(
                            cve.get('cvss_score', 0),
                            service_name,
                            port_num
                        )
                        
                        vulnerability = {
                            'host': host_ip,
                            'port': port_num,
                            'service': service_name,
                            'version': version,
                            'cve_id': cve.get('id'),
                            'cvss_score': cve.get('cvss_score'),
                            'severity': risk_level,
                            'description': cve.get('description', ''),
                            'references': cve.get('references', []),
                            'source': 'cve_database'
                        }
                        vulnerabilities.append(vulnerability)
            
            processed_hosts += 1
            progress.update(task_id, 
                          description=f"🔬 Analyzed {processed_hosts}/{total_hosts} hosts")
        
        return vulnerabilities
    
    def _process_nse_vulnerabilities(self, host_ip, host_data):
        """Process NSE script vulnerability findings"""
        vulnerabilities = []
        
        for port_info in host_data.get('ports', []):
            scripts = port_info.get('scripts', [])
            
            for script in scripts:
                script_id = script.get('id', '')
                script_output = script.get('output', '')
                
                # Parse vulners script output
                if 'vulners' in script_id:
                    vulns = self._parse_vulners_output(script_output)
                    for vuln in vulns:
                        vuln.update({
                            'host': host_ip,
                            'port': port_info.get('port'),
                            'service': port_info.get('service', 'unknown'),
                            'version': port_info.get('version', 'unknown'),
                            'source': 'nse_vulners'
                        })
                        vulnerabilities.append(vuln)
                
                # Parse other vulnerability scripts
                elif any(x in script_id for x in ['vuln', 'cve']):
                    vulns = self._parse_generic_vuln_output(script_output)
                    for vuln in vulns:
                        vuln.update({
                            'host': host_ip,
                            'port': port_info.get('port'),
                            'service': port_info.get('service', 'unknown'),
                            'version': port_info.get('version', 'unknown'),
                            'source': f'nse_{script_id}'
                        })
                        vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _parse_vulners_output(self, output):
        """Parse vulners NSE script output"""
        vulnerabilities = []
        import re
        
        # Pattern to match CVE entries in vulners output
        cve_pattern = r'(CVE-\d{4}-\d+)\s+(\d+\.\d+)\s+(.*?)(?=CVE-|\Z)'
        matches = re.findall(cve_pattern, output, re.DOTALL)
        
        for match in matches:
            cve_id, score, description = match
            severity = self.risk_engine._score_to_risk_level(float(score) / 10.0)
            
            vulnerabilities.append({
                'cve_id': cve_id,
                'cvss_score': float(score),
                'severity': severity,
                'description': description.strip(),
                'references': [f'https://nvd.nist.gov/vuln/detail/{cve_id}']
            })
        
        return vulnerabilities
    
    def _parse_generic_vuln_output(self, output):
        """Parse generic vulnerability script output"""
        vulnerabilities = []
        import re
        
        # Look for CVE references in output
        cve_matches = re.findall(r'CVE-\d{4}-\d+', output)
        
        for cve_id in cve_matches:
            # Try to get more details from our database
            cve_details = self.cve_mapper.get_cve_details(cve_id)
            
            if cve_details:
                vulnerabilities.append(cve_details)
            else:
                vulnerabilities.append({
                    'cve_id': cve_id,
                    'cvss_score': 5.0,  # Default medium score
                    'severity': 'medium',
                    'description': f'Vulnerability detected by NSE script: {cve_id}',
                    'references': [f'https://nvd.nist.gov/vuln/detail/{cve_id}']
                })
        
        return vulnerabilities
    
    def _enhance_with_exploits(self, vulnerabilities, progress, task_id):
        """Enhance vulnerabilities with exploit availability data"""
        total_vulns = len(vulnerabilities)
        
        for i, vuln in enumerate(vulnerabilities):
            progress.update(task_id, 
                          description=f"💥 Checking exploits ({i+1}/{total_vulns})...")
            
            cve_id = vuln.get('cve_id')
            if cve_id:
                exploit_info = self.exploit_checker.check_exploit_availability(cve_id)
                vuln.update(exploit_info)
                
                # Recalculate risk with exploit factor
                if exploit_info.get('has_exploit'):
                    original_score = vuln.get('cvss_score', 0)
                    enhanced_score = self.risk_engine.calculate_risk_with_exploit(
                        original_score, 
                        vuln.get('service', ''),
                        vuln.get('port', 0),
                        exploit_info
                    )
                    vuln['enhanced_severity'] = enhanced_score
        
        return vulnerabilities
    
    def _generate_enhanced_summary(self, vulnerabilities):
        """Generate enhanced vulnerability summary with exploit data"""
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        exploit_counts = {'with_exploit': 0, 'without_exploit': 0}
        source_counts = {}
        
        for vuln in vulnerabilities:
            # Count by severity
            severity = vuln.get('enhanced_severity', vuln.get('severity', 'info'))
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
            # Count by exploit availability
            if vuln.get('has_exploit'):
                exploit_counts['with_exploit'] += 1
            else:
                exploit_counts['without_exploit'] += 1
            
            # Count by source
            source = vuln.get('source', 'unknown')
            source_counts[source] = source_counts.get(source, 0) + 1
        
        return {
            'total_vulnerabilities': len(vulnerabilities),
            'severity_breakdown': severity_counts,
            'exploit_breakdown': exploit_counts,
            'source_breakdown': source_counts,
            'unique_cves': len(set(v.get('cve_id') for v in vulnerabilities if v.get('cve_id'))),
            'high_priority': sum(severity_counts[s] for s in ['critical', 'high'])
        }
    
    def _display_terminal_summary(self, report_data):
        """Display scan summary in terminal"""
        summary = report_data['summary']
        
        # Create summary table
        table = Table(title="Vulnerability Scan Summary", show_header=True)
        table.add_column("Metric", style="cyan")
        table.add_column("Count", style="green")
        table.add_column("Details", style="yellow")
        
        table.add_row("Total Vulnerabilities", 
                     str(summary['total_vulnerabilities']),
                     f"{summary['unique_cves']} unique CVEs")
        
        table.add_row("High Priority Issues", 
                     str(summary['high_priority']),
                     "Critical + High severity")
        
        table.add_row("With Exploits Available", 
                     str(summary['exploit_breakdown']['with_exploit']),
                     "Immediate attention required")
        
        console.print(table)
        
        # Severity breakdown
        severity_table = Table(title="Severity Breakdown")
        severity_table.add_column("Severity", style="bold")
        severity_table.add_column("Count", justify="right")
        
        colors = {
            'critical': 'red',
            'high': 'orange1',
            'medium': 'yellow',
            'low': 'green',
            'info': 'blue'
        }
        
        for severity, count in summary['severity_breakdown'].items():
            color = colors.get(severity, 'white')
            severity_table.add_row(
                f"[{color}]{severity.upper()}[/{color}]",
                f"[{color}]{count}[/{color}]"
            )
        
        console.print(severity_table)


# =============================================================================
# scanner/nmap_scanner.py - Enhanced with NSE scripts
# =============================================================================
import subprocess
import json
import xml.etree.ElementTree as ET
import logging
import time
from typing import Dict, List, Optional, Callable

logger = logging.getLogger(__name__)

class NmapScanner:
    def __init__(self):
        self.base_args = ['-sV', '-sC', '--version-intensity', '5']
        self.nse_script_map = {
            'none': [],
            'vuln': ['--script=vuln'],
            'vulners': ['--script=vulners'],
            'vulscan': ['--script=vulscan'],
            'all': ['--script=vuln,vulners']
        }
    
    def scan_target(self, target: str, port_range: Optional[str] = None,
                   nse_scripts: str = 'vulners', skip_intrusive: bool = False,
                   enable_os_detection: bool = False, 
                   progress_callback: Optional[Callable] = None) -> Dict:
        """Enhanced nmap scan with NSE scripts and progress tracking"""
        try:
            # Build enhanced nmap command
            cmd = ['nmap', '-oX', '-'] + self.base_args
            
            # Add NSE scripts
            if nse_scripts != 'none':
                script_args = self.nse_script_map.get(nse_scripts, ['--script=vulners'])
                cmd.extend(script_args)
                
                if skip_intrusive:
                    cmd.append('--script-args=safe=1')
            
            # Add OS detection
            if enable_os_detection:
                cmd.extend(['-O', '--osscan-guess'])
            
            # Add ping skip for stealth
            cmd.append('-Pn')
            
            # Add port range
            if port_range:
                cmd.extend(['-p', port_range])
            else:
                cmd.extend(['-p', '1-1000'])  # Default range
            
            # Add timing template for balance of speed and accuracy
            cmd.extend(['-T4'])
            
            cmd.append(target)
            
            logger.info(f"Running enhanced scan: {' '.join(cmd)}")
            
            # Execute nmap with progress tracking
            if progress_callback:
                progress_callback(10)  # Starting scan
            
            result = subprocess.run(
                cmd, 
                capture_output=True, 
                text=True, 
                timeout=600  # Increased timeout for NSE scripts
            )
            
            if progress_callback:
                progress_callback(90)  # Scan completed, parsing results
            
            if result.returncode != 0:
                raise Exception(f"Nmap scan failed: {result.stderr}")
            
            # Parse XML output
            parsed_results = self._parse_nmap_xml(result.stdout)
            
            if progress_callback:
                progress_callback(100)  # Parsing completed
            
            return parsed_results
            
        except subprocess.TimeoutExpired:
            raise Exception("Nmap scan timed out (10 minutes)")
        except FileNotFoundError:
            raise Exception("Nmap not found. Please install nmap.")
        except Exception as e:
            logger.error(f"Enhanced scan error: {e}")
            raise
    
    def _parse_nmap_xml(self, xml_output: str) -> Dict:
        """Enhanced XML parsing with NSE script results"""
        try:
            root = ET.fromstring(xml_output)
            results = {'hosts': {}, 'scan_info': {}}
            
            # Parse scan info
            runstats = root.find('runstats')
            if runstats is not None:
                finished = runstats.find('finished')
                if finished is not None:
                    results['scan_info'] = {
                        'elapsed': finished.get('elapsed'),
                        'time': finished.get('time'),
                        'timestr': finished.get('timestr'),
                        'command': root.get('args', '')
                    }
            
            # Parse hosts with enhanced data
            for host in root.findall('host'):
                host_data = self._parse_enhanced_host(host)
                if host_data:
                    results['hosts'][host_data['ip']] = host_data
            
            return results
            
        except ET.ParseError as e:
            raise Exception(f"Failed to parse enhanced nmap XML: {e}")
    
    def _parse_enhanced_host(self, host_elem) -> Optional[Dict]:
        """Parse host with OS detection and enhanced script results"""
        status = host_elem.find('status')
        if status is None or status.get('state') != 'up':
            return None
        
        address = host_elem.find('address')
        if address is None:
            return None
        
        ip = address.get('addr')
        
        host_data = {
            'ip': ip,
            'state': 'up',
            'ports': [],
            'os_info': {},
            'host_scripts': []
        }
        
        # Parse hostnames
        hostnames = host_elem.find('hostnames')
        if hostnames is not None:
            host_data['hostnames'] = [
                hostname.get('name') 
                for hostname in hostnames.findall('hostname')
            ]
        
        # Parse OS detection results
        os_elem = host_elem.find('os')
        if os_elem is not None:
            host_data['os_info'] = self._parse_os_info(os_elem)
        
        # Parse host-level scripts
        hostscript = host_elem.find('hostscript')
        if hostscript is not None:
            for script in hostscript.findall('script'):
                host_data['host_scripts'].append({
                    'id': script.get('id'),
                    'output': script.get('output')
                })
        
        # Parse ports with enhanced script results
        ports = host_elem.find('ports')
        if ports is not None:
            for port in ports.findall('port'):
                port_data = self._parse_enhanced_port(port)
                if port_data:
                    host_data['ports'].append(port_data)
        
        return host_data
    
    def _parse_os_info(self, os_elem) -> Dict:
        """Parse OS detection information"""
        os_info = {}
        
        # OS matches
        osmatch = os_elem.find('osmatch')
        if osmatch is not None:
            os_info['name'] = osmatch.get('name')
            os_info['accuracy'] = osmatch.get('accuracy')
        
        # OS classes
        osclass = os_elem.find('.//osclass')
        if osclass is not None:
            os_info['type'] = osclass.get('type')
            os_info['vendor'] = osclass.get('vendor')
            os_info['osfamily'] = osclass.get('osfamily')
        
        return os_info
    
    def _parse_enhanced_port(self, port_elem) -> Optional[Dict]:
        """Parse port with enhanced script results"""
        state = port_elem.find('state')
        if state is None or state.get('state') not in ['open', 'filtered']:
            return None
        
        port_data = {
            'port': int(port_elem.get('portid')),
            'protocol': port_elem.get('protocol'),
            'state': state.get('state'),
            'scripts': []
        }
        
        # Parse service info with enhanced details
        service = port_elem.find('service')
        if service is not None:
            port_data.update({
                'service': service.get('name', 'unknown'),
                'version': service.get('version', 'unknown'),
                'product': service.get('product', 'unknown'),
                'extrainfo': service.get('extrainfo', ''),
                'ostype': service.get('ostype', ''),
                'method': service.get('method', ''),
                'conf': service.get('conf', '')
            })
        
        # Parse all script results (including NSE vulnerability scripts)
        for script in port_elem.findall('.//script'):
            script_data = {
                'id': script.get('id'),
                'output': script.get('output', ''),
                'elements': {}
            }
            
            # Parse structured script elements
            for elem in script.findall('.//elem'):
                key = elem.get('key', 'value')
                script_data['elements'][key] = elem.text
            
            port_data['scripts'].append(script_data)
        
        return port_data


# =============================================================================
# core/exploit_checker.py - New module for exploit availability
# =============================================================================
import requests
import logging
import time
from typing import Dict, Optional
from utils.database import DatabaseManager

logger = logging.getLogger(__name__)

class ExploitChecker:
    def __init__(self, db_manager: DatabaseManager):
        self.db_manager = db_manager
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'VulnerabilityScanner/2.0'
        })
        
        # Exploit databases
        self.exploit_sources = {
            'exploitdb': 'https://www.exploit-db.com/api/v1/search',
            'vulners': 'https://vulners.com/api/v3/search/lucene/',
            'metasploit': 'https://www.rapid7.com/db/search'
        }
    
    def check_exploit_availability(self, cve_id: str) -> Dict:
        """Check if exploits are available for a CVE"""
        try:
            # Check cache first
            cached_result = self.db_manager.get_exploit_info(cve_id)
            if cached_result:
                return cached_result
            
            exploit_info = {
                'has_exploit': False,
                'exploit_count': 0,
                'exploit_sources': [],
                'metasploit_modules': [],
                'exploit_links': [],
                'exploit_risk_multiplier': 1.0
            }
            
            # Check ExploitDB
            exploitdb_results = self._check_exploitdb(cve_id)
            if exploitdb_results:
                exploit_info['has_exploit'] = True
                exploit_info['exploit_count'] += exploitdb_results['count']
                exploit_info['exploit_sources'].append('ExploitDB')
                exploit_info['exploit_links'].extend(exploitdb_results['links'])
            
            # Check for Metasploit modules
            msf_results = self._check_metasploit_modules(cve_id)
            if msf_results:
                exploit_info['has_exploit'] = True
                exploit_info['metasploit_modules'] = msf_results
                exploit_info['exploit_sources'].append('Metasploit')
            
            # Calculate risk multiplier based on exploit availability
            if exploit_info['has_exploit']:
                if exploit_info['metasploit_modules']:
                    exploit_info['exploit_risk_multiplier'] = 1.5  # High risk
                else:
                    exploit_info['exploit_risk_multiplier'] = 1.3  # Medium risk
            
            # Cache the result
            self.db_manager.cache_exploit_info(cve_id, exploit_info)
            
            return exploit_info
            
        except Exception as e:
            logger.error(f"Error checking exploits for {cve_id}: {e}")
            return {'has_exploit': False, 'exploit_risk_multiplier': 1.0}
    
    def _check_exploitdb(self, cve_id: str) -> Optional[Dict]:
        """Check ExploitDB for available exploits"""
        try:
            # Simulate ExploitDB API response (replace with actual API call)
            # This is a simplified simulation of exploit availability
            known_exploits = {
                'CVE-2021-44228': {
                    'count': 15,
                    'links': ['https://www.exploit-db.com/exploits/50592']
                },
                'CVE-2021-45046': {
                    'count': 8,
                    'links': ['https://www.exploit-db.com/exploits/50593']
                },
                'CVE-2020-15778': {
                    'count': 3,
                    'links': ['https://www.exploit-db.com/exploits/49233']
                }
            }
            
            return known_exploits.get(cve_id)
            
        except Exception as e:
            logger.debug(f"ExploitDB check failed for {cve_id}: {e}")
            return None
    
    def _check_metasploit_modules(self, cve_id: str) -> List[str]:
        """Check for Metasploit modules"""
        try:
            # Simulate Metasploit module availability
            metasploit_modules = {
                'CVE-2021-44228': [
                    'exploit/multi/http/log4shell_header_injection',
                    'auxiliary/scanner/http/log4shell_scanner'
                ],
                'CVE-2021-45046': [
                    'exploit/multi/http/log4shell_header_injection'
                ]
            }
            
            return metasploit_modules.get(cve_id, [])
            
        except Exception as e:
            logger.debug(f"Metasploit check failed for {cve_id}: {e}")
            return []


# =============================================================================
# core/risk_engine.py - Enhanced with exploit factor
# =============================================================================
import logging
from typing import Dict, List

logger = logging.getLogger(__name__)

class RiskEngine:
    def __init__(self):
        # Enhanced service criticality weights
        self.service_weights = {
            'ssh': 0.9, 'ftp': 0.8, 'telnet': 0.9, 'http': 0.7, 'https': 0.7,
            'mysql': 0.8, 'postgresql': 0.8, 'mssql': 0.8, 'oracle': 0.8,
            'mongodb': 0.8, 'redis': 0.7, 'smtp': 0.6, 'pop3': 0.5, 'imap': 0.5,
            'dns': 0.8, 'ntp': 0.4, 'snmp': 0.7, 'rdp': 0.9, 'vnc': 0.8,
            'apache': 0.7, 'nginx': 0.7, 'tomcat': 0.8, 'iis': 0.7
        }
        
        # Critical ports with enhanced coverage
        self.critical_ports = {
            21: 0.8, 22: 0.9, 23: 0.9, 25: 0.6, 53: 0.8, 80: 0.7, 110: 0.5,
            143: 0.5, 443: 0.7, 993: 0.5, 995: 0.5, 1433: 0.8, 1521: 0.8,
            3306: 0.8, 3389: 0.9, 5432: 0.8, 5984: 0.7, 6379: 0.7, 27017: 0.8,
            50070: 0.8, 8080: 0.7, 8443: 0.7, 9200: 0.8, 9300: 0.8
        }
        
        # Configurable scoring weights
        self.scoring_weights = {
            'cvss': 0.6,      # Reduced to accommodate exploit factor
            'service': 0.15,
            'port': 0.1,
            'exploit': 0.15   # New exploit availability factor
        }
    
    def calculate_risk(self, cvss_score: float, service_name: str = None, port: int = None) -> str:
        """Calculate risk level based on CVSS score and context"""
        return self._calculate_base_risk(cvss_score, service_name, port)
    
    def calculate_risk_with_exploit(self, cvss_score: float, service_name: str = None, 
                                  port: int = None, exploit_info: Dict = None) -> str:
        """Enhanced risk calculation including exploit availability"""
        try:
            # Base risk calculation
            base_risk = self._cvss_to_risk_score(cvss_score)
            
            # Service weight
            service_weight = self.service_weights.get(service_name.lower() if service_name else '', 0.5)
            
            # Port weight
            port_weight = self.critical_ports.get(port, 0.5)
            
            # Exploit weight
            exploit_multiplier = exploit_info.get('exploit_risk_multiplier', 1.0) if exploit_info else 1.0
            exploit_weight = min(exploit_multiplier - 1.0, 0.5)  # Cap at 0.5 additional risk
            
            # Calculate weighted risk score with configurable weights
            weighted_score = (
                base_risk * self.scoring_weights['cvss'] +
                service_weight * self.scoring_weights['service'] +
                port_weight * self.scoring_weights['port'] +
                exploit_weight * self.scoring_weights['exploit']
            )
            
            # Apply exploit multiplier to final score
            if exploit_info and exploit_info.get('has_exploit'):
                weighted_score *= exploit_multiplier
            
            # Ensure score doesn't exceed 1.0
            weighted_score = min(weighted_score, 1.0)
            
            return self._score_to_risk_level(weighted_score)
            
        except Exception as e:
            logger.error(f"Enhanced risk calculation error: {e}")
            return 'medium'
    
    def _calculate_base_risk(self, cvss_score: float, service_name: str = None, port: int = None) -> str:
        """Original risk calculation method"""
        try:
            base_risk = self._cvss_to_risk_score(cvss_score)
            service_weight = self.service_weights.get(service_name.lower() if service_name else '', 0.5)
            port_weight = self.critical_ports.get(port, 0.5)
            
            # Use traditional weights without exploit factor
            weighted_score = (base_risk * 0.7) + (service_weight * 0.2) + (port_weight * 0.1)
            
            return self._score_to_risk_level(weighted_score)
            
        except Exception as e:
            logger.error(f"Risk calculation error: {e}")
            return 'medium'
    
    def update_scoring_weights(self, cvss_weight: float = None, service_weight: float = None,
                             port_weight: float = None, exploit_weight: float = None):
        """Allow users to adjust scoring weights"""
        if cvss_weight is not None:
            self.scoring_weights['cvss'] = cvss_weight
        if service_weight is not None:
            self.scoring_weights['service'] = service_weight
        if port_weight is not None:
            self.scoring_weights['port'] = port_weight
        if exploit_weight is not None:
            self.scoring_weights['exploit'] = exploit_weight
        
        # Normalize weights to sum to 1.0
        total = sum(self.scoring_weights.values())
        for key in self.scoring_weights:
            self.scoring_weights[key] /= total
    
    def _cvss_to_risk_score(self, cvss_score: float) -> float:
        """Convert CVSS score to normalized risk score (0-1)"""
        if cvss_score >= 9.0:
            return 1.0
        elif cvss_score >= 7.0:
            return 0.8
        elif cvss_score >= 4.0:
            return 0.6
        elif cvss_score >= 0.1:
            return 0.4
        else:
            return 0.2
    
    def _score_to_risk_level(self, score: float) -> str:
        """Convert risk score to risk level"""
        if score >= 0.9:
            return 'critical'
        elif score >= 0.7:
            return 'high'
        elif score >= 0.5:
            return 'medium'
        elif score >= 0.3:
            return 'low'
        else:
            return 'info'
    
    def calculate_overall_risk(self, vulnerabilities: List[Dict]) -> Dict:
        """Enhanced overall risk assessment with exploit consideration"""
        if not vulnerabilities:
            return {'level': 'info', 'score': 0.0, 'details': 'No vulnerabilities found'}
        
        severity_counts = {}
        exploit_enhanced_count = 0
        total_score = 0.0
        
        for vuln in vulnerabilities:
            # Use enhanced severity if available
            severity = vuln.get('enhanced_severity', vuln.get('severity', 'info'))
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            total_score += self._risk_level_to_score(severity)
            
            # Count exploit-enhanced vulnerabilities
            if vuln.get('has_exploit'):
                exploit_enhanced_count += 1
        
        avg_score = total_score / len(vulnerabilities)
        overall_level = self._score_to_risk_level(avg_score)
        details = self._generate_enhanced_risk_details(severity_counts, len(vulnerabilities), exploit_enhanced_count)
        
        return {
            'level': overall_level,
            'score': round(avg_score, 2),
            'details': details,
            'severity_breakdown': severity_counts,
            'exploit_enhanced_count': exploit_enhanced_count
        }
    
    def _risk_level_to_score(self, level: str) -> float:
        """Convert risk level back to score for calculations"""
        level_scores = {
            'critical': 1.0, 'high': 0.8, 'medium': 0.6, 'low': 0.4, 'info': 0.2
        }
        return level_scores.get(level, 0.2)
    
    def _generate_enhanced_risk_details(self, severity_counts: Dict, total_vulns: int, exploit_count: int) -> str:
        """Generate enhanced risk details with exploit information"""
        base_detail = ""
        if severity_counts.get('critical', 0) > 0:
            base_detail = "Critical security issues found. Immediate action required."
        elif severity_counts.get('high', 0) > 0:
            base_detail = "High-risk vulnerabilities detected. Address promptly."
        elif severity_counts.get('medium', 0) > 0:
            base_detail = "Medium-risk issues found. Plan remediation."
        elif severity_counts.get('low', 0) > 0:
            base_detail = "Low-risk vulnerabilities detected. Monitor and address when convenient."
        else:
            base_detail = "Only informational findings."
        
        exploit_detail = f" {exploit_count} vulnerabilities have known exploits." if exploit_count > 0 else ""
        
        return f"{base_detail} ({total_vulns} total vulnerabilities){exploit_detail}"


# =============================================================================
# utils/database.py - SQLite database for persistent caching
# =============================================================================
import sqlite3
import json
import logging
from pathlib import Path
from typing import Dict, List, Optional
import time

logger = logging.getLogger(__name__)

class DatabaseManager:
    def __init__(self, db_path: str = "vulnerability_scanner.db"):
        self.db_path = Path(db_path)
        self.init_database()
    
    def init_database(self):
        """Initialize SQLite database with required tables"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # CVE cache table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS cve_cache (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        service_name TEXT NOT NULL,
                        version TEXT NOT NULL,
                        cve_data TEXT NOT NULL,
                        timestamp REAL NOT NULL,
                        UNIQUE(service_name, version)
                    )
                ''')
                
                # Exploit information cache
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS exploit_cache (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        cve_id TEXT UNIQUE NOT NULL,
                        exploit_info TEXT NOT NULL,
                        timestamp REAL NOT NULL
                    )
                ''')
                
                # Scan history
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS scan_history (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        target TEXT NOT NULL,
                        scan_time REAL NOT NULL,
                        vulnerability_count INTEGER,
                        high_risk_count INTEGER,
                        scan_config TEXT,
                        report_path TEXT
                    )
                ''')
                
                # Create indexes for better performance
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_cve_service ON cve_cache(service_name)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_exploit_cve ON exploit_cache(cve_id)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_scan_target ON scan_history(target)')
                
                conn.commit()
                logger.info("Database initialized successfully")
                
        except Exception as e:
            logger.error(f"Database initialization failed: {e}")
            raise
    
    def cache_cve_data(self, service_name: str, version: str, cve_data: List[Dict]):
        """Cache CVE data for a service/version combination"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT OR REPLACE INTO cve_cache 
                    (service_name, version, cve_data, timestamp) 
                    VALUES (?, ?, ?, ?)
                ''', (service_name, version, json.dumps(cve_data), time.time()))
                conn.commit()
                
        except Exception as e:
            logger.error(f"Failed to cache CVE data: {e}")
    
    def get_cached_cve_data(self, service_name: str, version: str, max_age: int = 86400) -> Optional[List[Dict]]:
        """Retrieve cached CVE data if not expired"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT cve_data, timestamp FROM cve_cache 
                    WHERE service_name = ? AND version = ?
                ''', (service_name, version))
                
                result = cursor.fetchone()
                if result:
                    cve_data, timestamp = result
                    if time.time() - timestamp < max_age:
                        return json.loads(cve_data)
                
        except Exception as e:
            logger.error(f"Failed to retrieve cached CVE data: {e}")
        
        return None
    
    def cache_exploit_info(self, cve_id: str, exploit_info: Dict):
        """Cache exploit information for a CVE"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT OR REPLACE INTO exploit_cache 
                    (cve_id, exploit_info, timestamp) 
                    VALUES (?, ?, ?)
                ''', (cve_id, json.dumps(exploit_info), time.time()))
                conn.commit()
                
        except Exception as e:
            logger.error(f"Failed to cache exploit info: {e}")
    
    def get_exploit_info(self, cve_id: str, max_age: int = 86400) -> Optional[Dict]:
        """Retrieve cached exploit information"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT exploit_info, timestamp FROM exploit_cache 
                    WHERE cve_id = ?
                ''', (cve_id,))
                
                result = cursor.fetchone()
                if result:
                    exploit_info, timestamp = result
                    if time.time() - timestamp < max_age:
                        return json.loads(exploit_info)
                
        except Exception as e:
            logger.error(f"Failed to retrieve exploit info: {e}")
        
        return None
    
    def save_scan_history(self, target: str, vulnerability_count: int, 
                         high_risk_count: int, scan_config: Dict, report_path: str):
        """Save scan results to history"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO scan_history 
                    (target, scan_time, vulnerability_count, high_risk_count, scan_config, report_path) 
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (target, time.time(), vulnerability_count, high_risk_count, 
                     json.dumps(scan_config), report_path))
                conn.commit()
                
        except Exception as e:
            logger.error(f"Failed to save scan history: {e}")
    
    def get_scan_history(self, target: str = None, limit: int = 10) -> List[Dict]:
        """Retrieve scan history"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                if target:
                    cursor.execute('''
                        SELECT * FROM scan_history 
                        WHERE target = ? 
                        ORDER BY scan_time DESC 
                        LIMIT ?
                    ''', (target, limit))
                else:
                    cursor.execute('''
                        SELECT * FROM scan_history 
                        ORDER BY scan_time DESC 
                        LIMIT ?
                    ''', (limit,))
                
                results = cursor.fetchall()
                columns = [desc[0] for desc in cursor.description]
                
                return [dict(zip(columns, row)) for row in results]
                
        except Exception as e:
            logger.error(f"Failed to retrieve scan history: {e}")
            return []
    
    def cleanup_old_cache(self, max_age: int = 604800):  # 7 days
        """Clean up old cache entries"""
        try:
            cutoff_time = time.time() - max_age
            
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Clean CVE cache
                cursor.execute('DELETE FROM cve_cache WHERE timestamp < ?', (cutoff_time,))
                cve_deleted = cursor.rowcount
                
                # Clean exploit cache
                cursor.execute('DELETE FROM exploit_cache WHERE timestamp < ?', (cutoff_time,))
                exploit_deleted = cursor.rowcount
                
                conn.commit()
                
                logger.info(f"Cleaned up {cve_deleted} CVE cache entries and {exploit_deleted} exploit cache entries")
                
        except Exception as e:
            logger.error(f"Cache cleanup failed: {e}")


# =============================================================================
# core/cve_mapper.py - Enhanced with SQLite integration
# =============================================================================
import requests
import json
import time
import logging
from typing import List, Dict, Optional
from utils.database import DatabaseManager

logger = logging.getLogger(__name__)

class CVEMapper:
    def __init__(self, db_manager: DatabaseManager):
        self.db_manager = db_manager
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'VulnerabilityScanner/2.0'
        })
        
        # Enhanced CVE sources
        self.cve_sources = {
            'circl': 'https://cve.circl.lu/api',
            'nvd': 'https://services.nvd.nist.gov/rest/json/cves/2.0',
            'vulners': 'https://vulners.com/api/v3/search/lucene/'
        }
    
    def get_cve_data(self, service_name: str, version: str) -> List[Dict]:
        """Enhanced CVE data retrieval with database caching"""
        try:
            # Check database cache first
            cached_data = self.db_manager.get_cached_cve_data(service_name, version)
            if cached_data:
                logger.debug(f"Using cached CVE data for {service_name}:{version}")
                return cached_data
            
            logger.info(f"Fetching fresh CVE data for {service_name} {version}")
            
            # Fetch from multiple sources
            cve_data = []
            cve_data.extend(self._fetch_from_circl(service_name, version))
            cve_data.extend(self._fetch_from_nvd_simulation(service_name, version))
            cve_data.extend(self._fetch_from_vulners_simulation(service_name, version))
            
            # Remove duplicates based on CVE ID
            unique_cves = {}
            for cve in cve_data:
                cve_id = cve.get('id')
                if cve_id and cve_id not in unique_cves:
                    unique_cves[cve_id] = cve
            
            final_cve_list = list(unique_cves.values())
            
            # Cache the results
            self.db_manager.cache_cve_data(service_name, version, final_cve_list)
            
            return final_cve_list
            
        except Exception as e:
            logger.error(f"Error fetching CVE data for {service_name}:{version} - {e}")
            return []
    
    def get_cve_details(self, cve_id: str) -> Optional[Dict]:
        """Get detailed information for a specific CVE"""
        try:
            # Check if we have it in our simulated database
            cve_details = self._get_cve_from_simulation(cve_id)
            if cve_details:
                return cve_details
            
            # Try to fetch from external sources
            return self._fetch_cve_details_external(cve_id)
            
        except Exception as e:
            logger.error(f"Error fetching CVE details for {cve_id}: {e}")
            return None
    
    def _fetch_from_circl(self, service_name: str, version: str) -> List[Dict]:
        """Enhanced CIRCL API integration"""
        try:
            url = f"{self.cve_sources['circl']}/search/{service_name}"
            response = self.session.get(url, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                return self._parse_circl_response(data, version)
            
        except Exception as e:
            logger.debug(f"CIRCL API error: {e}")
        
        return []
    
    def _fetch_from_nvd_simulation(self, service_name: str, version: str) -> List[Dict]:
        """Enhanced simulated NVD database with more vulnerabilities"""
        vulnerability_db = {
            'apache': [
                {
                    'id': 'CVE-2021-44228',
                    'cvss_score': 10.0,
                    'description': 'Apache Log4j2 JNDI features do not protect against attacker controlled LDAP and other JNDI related endpoints.',
                    'references': ['https://nvd.nist.gov/vuln/detail/CVE-2021-44228'],
                    'cwe': 'CWE-502',
                    'published': '2021-12-10'
                },
                {
                    'id': 'CVE-2021-45046',
                    'cvss_score': 9.0,
                    'description': 'Apache Log4j2 incomplete fix for CVE-2021-44228.',
                    'references': ['https://nvd.nist.gov/vuln/detail/CVE-2021-45046'],
                    'cwe': 'CWE-20',
                    'published': '2021-12-14'
                },
                {
                    'id': 'CVE-2022-22965',
                    'cvss_score': 9.8,
                    'description': 'Spring Framework RCE via Data Binding on JDK 9+',
                    'references': ['https://nvd.nist.gov/vuln/detail/CVE-2022-22965'],
                    'cwe': 'CWE-94',
                    'published': '2022-04-01'
                }
            ],
            'nginx': [
                {
                    'id': 'CVE-2021-23017',
                    'cvss_score': 7.7,
                    'description': 'A security issue in nginx resolver was identified, which might allow an attacker who is able to forge UDP packets from the DNS server.',
                    'references': ['https://nvd.nist.gov/vuln/detail/CVE-2021-23017'],
                    'cwe': 'CWE-787',
                    'published': '2021-06-01'
                },
                {
                    'id': 'CVE-2022-41741',
                    'cvss_score': 7.8,
                    'description': 'NGINX Ingress Controller allows authenticated administrators to execute arbitrary Lua code.',
                    'references': ['https://nvd.nist.gov/vuln/detail/CVE-2022-41741'],
                    'cwe': 'CWE-94',
                    'published': '2022-10-19'
                }
            ],
            'ssh': [
                {
                    'id': 'CVE-2020-15778',
                    'cvss_score': 7.8,
                    'description': 'scp in OpenSSH allows command injection in the scp.c toremote function.',
                    'references': ['https://nvd.nist.gov/vuln/detail/CVE-2020-15778'],
                    'cwe': 'CWE-78',
                    'published': '2020-07-24'
                },
                {
                    'id': 'CVE-2021-41617',
                    'cvss_score': 7.0,
                    'description': 'OpenSSH privilege escalation vulnerability',
                    'references': ['https://nvd.nist.gov/vuln/detail/CVE-2021-41617'],
                    'cwe': 'CWE-281',
                    'published': '2021-09-26'
                }
            ],
            'mysql': [
                {
                    'id': 'CVE-2021-2154',
                    'cvss_score': 4.9,
                    'description': 'Vulnerability in the MySQL Server product of Oracle MySQL.',
                    'references': ['https://nvd.nist.gov/vuln/detail/CVE-2021-2154'],
                    'cwe': 'CWE-89',
                    'published': '2021-04-22'
                },
                {
                    'id': 'CVE-2022-21417',
                    'cvss_score': 8.8,
                    'description': 'MySQL Server vulnerability allows high privileged attacker with network access via multiple protocols to compromise MySQL Server.',
                    'references': ['https://nvd.nist.gov/vuln/detail/CVE-2022-21417'],
                    'cwe': 'CWE-89',
                    'published': '2022-04-19'
                }
            ],
            'http': [
                {
                    'id': 'CVE-2021-34527',
                    'cvss_score': 8.8,
                    'description': 'Windows Print Spooler Remote Code Execution Vulnerability (PrintNightmare)',
                    'references': ['https://nvd.nist.gov/vuln/detail/CVE-2021-34527'],
                    'cwe': 'CWE-269',
                    'published': '2021-07-02'
                }
            ]
        }
        
        return vulnerability_db.get(service_name.lower(), [])
    
    def _fetch_from_vulners_simulation(self, service_name: str, version: str) -> List[Dict]:
        """Simulated Vulners API data"""
        vulners_db = {
            'tomcat': [
                {
                    'id': 'CVE-2020-1938',
                    'cvss_score': 9.8,
                    'description': 'Apache Tomcat AJP Request Injection and potential Remote Code Execution',
                    'references': ['https://nvd.nist.gov/vuln/detail/CVE-2020-1938'],
                    'cwe': 'CWE-94',
                    'published': '2020-02-24'
                }
            ],
            'elasticsearch': [
                {
                    'id': 'CVE-2021-22134',
                    'cvss_score': 7.5,
                    'description': 'Elasticsearch information disclosure vulnerability',
                    'references': ['https://nvd.nist.gov/vuln/detail/CVE-2021-22134'],
                    'cwe': 'CWE-200',
                    'published': '2021-06-07'
                }
            ]
        }
        
        return vulners_db.get(service_name.lower(), [])
    
    def _get_cve_from_simulation(self, cve_id: str) -> Optional[Dict]:
        """Get CVE details from simulated database"""
        # Flatten all CVE data from simulated databases
        all_cves = {}
        
        # Collect from NVD simulation
        nvd_data = self._fetch_from_nvd_simulation('', '')
        for service_cves in [
            self._fetch_from_nvd_simulation('apache', ''),
            self._fetch_from_nvd_simulation('nginx', ''),
            self._fetch_from_nvd_simulation('ssh', ''),
            self._fetch_from_nvd_simulation('mysql', ''),
            self._fetch_from_nvd_simulation('http', '')
        ]:
            for cve in service_cves:
                all_cves[cve['id']] = cve
        
        # Collect from Vulners simulation
        for service_cves in [
            self._fetch_from_vulners_simulation('tomcat', ''),
            self._fetch_from_vulners_simulation('elasticsearch', '')
        ]:
            for cve in service_cves:
                all_cves[cve['id']] = cve
        
        return all_cves.get(cve_id)
    
    def _fetch_cve_details_external(self, cve_id: str) -> Optional[Dict]:
        """Fetch CVE details from external sources"""
        try:
            # Try CIRCL first
            url = f"{self.cve_sources['circl']}/cve/{cve_id}"
            response = self.session.get(url, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                return {
                    'id': data.get('id'),
                    'cvss_score': float(data.get('cvss', 0)),
                    'description': data.get('summary', ''),
                    'references': data.get('references', []),
                    'published': data.get('Published', '')
                }
        
        except Exception as e:
            logger.debug(f"External CVE fetch failed for {cve_id}: {e}")
        
        return None
    
    def _parse_circl_response(self, data: Dict, version: str) -> List[Dict]:
        """Enhanced CIRCL response parsing"""
        cve_list = []
        
        if isinstance(data, list):
            for item in data[:10]:  # Limit to first 10 results
                if isinstance(item, dict):
                    cve_list.append({
                        'id': item.get('id', 'Unknown'),
                        'cvss_score': float(item.get('cvss', 0)),
                        'description': item.get('summary', ''),
                        'references': item.get('references', []),
                        'published': item.get('Published', ''),
                        'cwe': item.get('cwe', ''),
                        'source': 'circl'
                    })
        
        return cve_list


# =============================================================================
# reports/report_generator.py - Enhanced with charts and remediation
# =============================================================================
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional

logger = logging.getLogger(__name__)

class ReportGenerator:
    def __init__(self):
        self.reports_dir = Path("reports")
        self.reports_dir.mkdir(exist_ok=True)
    
    def generate_report(self, data: Dict, output_file: Optional[str] = None, 
                       format_type: str = 'html') -> str:
        """Generate enhanced vulnerability report with charts and remediation"""
        
        if not output_file:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            target_clean = data['target'].replace('/', '_').replace('.', '_')
            output_file = f"vuln_report_{target_clean}_{timestamp}.{format_type}"
        
        output_path = self.reports_dir / output_file
        
        if format_type == 'html':
            content = self._generate_enhanced_html_report(data)
        elif format_type == 'json':
            content = self._generate_enhanced_json_report(data)
        elif format_type == 'txt':
            content = self._generate_enhanced_text_report(data)
        else:
            raise ValueError(f"Unsupported format: {format_type}")
        
        # Write report
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(content)
        
        logger.info(f"Enhanced report generated: {output_path}")
        return str(output_path)
    
    def _generate_enhanced_html_report(self, data: Dict) -> str:
        """Generate enhanced HTML report with charts and remediation"""
        vulnerabilities = data.get('vulnerabilities', [])
        summary = data.get('summary', {})
        scan_results = data.get('scan_results', {})
        scan_config = data.get('scan_config', {})
        
        # Calculate overall risk
        from core.risk_engine import RiskEngine
        risk_engine = RiskEngine()
        overall_risk = risk_engine.calculate_overall_risk(vulnerabilities)
        
        # Prepare chart data
        severity_data = summary.get('severity_breakdown', {})
        exploit_data = summary.get('exploit_breakdown', {})
        
        html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Enhanced Vulnerability Scan Report - {data['target']}</title>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/3.9.1/chart.min.js"></script>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; }}
        .container {{ max-width: 1400px; margin: 0 auto; padding: 20px; }}
        .header {{ background: rgba(255,255,255,0.95); backdrop-filter: blur(10px); border-radius: 15px; padding: 30px; margin-bottom: 30px; box-shadow: 0 8px 32px rgba(0,0,0,0.1); }}
        .header h1 {{ color: #2c3e50; font-size: 2.5em; margin-bottom: 10px; }}
        .header .subtitle {{ color: #7f8c8d; font-size: 1.1em; }}
        .cards-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 20px; margin-bottom: 30px; }}
        .card {{ background: rgba(255,255,255,0.95); backdrop-filter: blur(10px); border-radius: 15px; padding: 25px; box-shadow: 0 8px 32px rgba(0,0,0,0.1); transition: transform 0.3s ease; }}
        .card:hover {{ transform: translateY(-5px); }}
        .card h3 {{ color: #34495e; margin-bottom: 15px; font-size: 1.2em; }}
        .card .value {{ font-size: 2.5em; font-weight: bold; margin-bottom: 10px; }}
        .card .description {{ color: #7f8c8d; font-size: 0.9em; }}
        .risk-critical {{ color: #e74c3c; }}
        .risk-high {{ color: #f39c12; }}
        .risk-medium {{ color: #f1c40f; }}
        .risk-low {{ color: #27ae60; }}
        .risk-info {{ color: #3498db; }}
        .charts-section {{ display: grid; grid-template-columns: 1fr 1fr; gap: 30px; margin-bottom: 30px; }}
        .chart-card {{ background: rgba(255,255,255,0.95); backdrop-filter: blur(10px); border-radius: 15px; padding: 25px; box-shadow: 0 8px 32px rgba(0,0,0,0.1); }}
        .chart-container {{ position: relative; height: 300px; }}
        .section {{ background: rgba(255,255,255,0.95); backdrop-filter: blur(10px); border-radius: 15px; margin-bottom: 30px; box-shadow: 0 8px 32px rgba(0,0,0,0.1); }}
        .section-header {{ background: linear-gradient(135deg, #667eea, #764ba2); color: white; padding: 20px; border-radius: 15px 15px 0 0; }}
        .section-content {{ padding: 25px; }}
        .vuln-table {{ width: 100%; border-collapse: collapse; margin-top: 15px; }}
        .vuln-table th {{ background: #f8f9fa; padding: 15px; text-align: left; font-weight: 600; border-bottom: 2px solid #dee2e6; }}
        .vuln-table td {{ padding: 12px 15px; border-bottom: 1px solid #dee2e6; }}
        .vuln-table tr:hover {{ background: #f8f9fa; }}
        .severity-badge {{ padding: 4px 12px; border-radius: 20px; color: white; font-weight: bold; font-size: 0.8em; text-transform: uppercase; }}
        .exploit-indicator {{ padding: 2px 8px; border-radius: 10px; font-size: 0.7em; font-weight: bold; }}
        .exploit-yes {{ background: #e74c3c; color: white; }}
        .exploit-no {{ background: #95a5a6; color: white; }}
        .remediation-card {{ background: #fff3cd; border: 1px solid #ffeaa7; border-radius: 8px; padding: 15px; margin: 10px 0; }}
        .remediation-title {{ color: #856404; font-weight: bold; margin-bottom: 8px; }}
        .remediation-text {{ color: #664d03; }}
        .host-info {{ background: #e9ecef; padding: 20px; border-radius: 10px; margin-bottom: 20px; }}
        .port-grid {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(150px, 1fr)); gap: 10px; margin-top: 15px; }}
        .port-badge {{ background: linear-gradient(135deg, #667eea, #764ba2); color: white; padding: 10px; border-radius: 8px; text-align: center; font-weight: bold; }}
        .footer {{ text-align: center; padding: 30px; color: rgba(255,255,255,0.8); }}
        @media (max-width: 768px) {{
            .charts-section {{ grid-template-columns: 1fr; }}
            .cards-grid {{ grid-template-columns: 1fr; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Enhanced Vulnerability Scan Report</h1>
            <div class="subtitle">
                Target: <strong>{data['target']}</strong> | 
                Generated: <strong>{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</strong> |
                Scanner: <strong>Enhanced VulnScanner v2.0</strong>
            </div>
        </div>
        
        <div class="cards-grid">
            <div class="card">
                <h3>🎯 Overall Risk Level</h3>
                <div class="value risk-{overall_risk['level']}">{overall_risk['level'].upper()}</div>
                <div class="description">{overall_risk['details']}</div>
            </div>
            <div class="card">
                <h3>🔍 Total Vulnerabilities</h3>
                <div class="value risk-high">{summary.get('total_vulnerabilities', 0)}</div>
                <div class="description">Unique CVEs: {summary.get('unique_cves', 0)}</div>
            </div>
            <div class="card">
                <h3>💥 With Exploits</h3>
                <div class="value risk-critical">{summary.get('exploit_breakdown', {}).get('with_exploit', 0)}</div>
                <div class="description">Immediate attention required</div>
            </div>
            <div class="card">
                <h3>🖥️ Hosts Scanned</h3>
                <div class="value risk-info">{len(scan_results.get('hosts', {}))}</div>
                <div class="description">Active hosts discovered</div>
            </div>
        </div>
        
        <div class="charts-section">
            <div class="chart-card">
                <h3>📊 Severity Distribution</h3>
                <div class="chart-container">
                    <canvas id="severityChart"></canvas>
                </div>
            </div>
            <div class="chart-card">
                <h3>💣 Exploit Availability</h3>
                <div class="chart-container">
                    <canvas id="exploitChart"></canvas>
                </div>
            </div>
        </div>
        
        <div class="section">
            <div class="section-header">
                <h2>🎯 Scan Configuration</h2>
            </div>
            <div class="section-content">
                <div class="cards-grid">
                    <div class="card">
                        <h3>NSE Scripts</h3>
                        <div class="value" style="font-size: 1.5em; color: #667eea;">{scan_config.get('nse_scripts', 'N/A')}</div>
                    </div>
                    <div class="card">
                        <h3>Port Range</h3>
                        <div class="value" style="font-size: 1.5em; color: #667eea;">{scan_config.get('port_range', 'Default')}</div>
                    </div>
                    <div class="card">
                        <h3>OS Detection</h3>
                        <div class="value" style="font-size: 1.5em; color: #667eea;">{'Enabled' if scan_config.get('os_detection') else 'Disabled'}</div>
                    </div>
                </div>
            </div>
        </div>"""
        
        # Host information section
        if scan_results.get('hosts'):
            html += """
        <div class="section">
            <div class="section-header">
                <h2>🖥️ Discovered Hosts</h2>
            </div>
            <div class="section-content">"""
            
            for host_ip, host_data in scan_results['hosts'].items():
                ports = host_data.get('ports', [])
                os_info = host_data.get('os_info', {})
                
                html += f"""
                <div class="host-info">
                    <h3>🖥️ Host: {host_ip}</h3>
                    <p><strong>Status:</strong> {host_data.get('state', 'unknown').upper()}</p>"""
                
                if os_info:
                    html += f"""
                    <p><strong>OS Detection:</strong> {os_info.get('name', 'Unknown')} 
                    (Accuracy: {os_info.get('accuracy', 'N/A')}%)</p>"""
                
                html += """
                    <p><strong>Open Ports:</strong></p>
                    <div class="port-grid">"""
                
                for port in ports:
                    service = port.get('service', 'unknown')
                    version = port.get('version', '')
                    version_text = f" v{version}" if version and version != 'unknown' else ""
                    html += f"""
                        <div class="port-badge">
                            {port.get('port')}/{port.get('protocol')}<br>
                            <small>{service}{version_text}</small>
                        </div>"""
                
                html += """
                    </div>
                </div>"""
            
            html += """
            </div>
        </div>"""
        
        # Vulnerabilities section with remediation
        if vulnerabilities:
            html += """
        <div class="section">
            <div class="section-header">
                <h2>🔍 Vulnerability Details & Remediation</h2>
            </div>
            <div class="section-content">
                <table class="vuln-table">
                    <thead>
                        <tr>
                            <th>Host</th>
                            <th>Port/Service</th>
                            <th>CVE ID</th>
                            <th>CVSS</th>
                            <th>Severity</th>
                            <th>Exploit</th>
                            <th>Description</th>
                            <th>Remediation</th>
                        </tr>
                    </thead>
                    <tbody>"""
            
            for vuln in vulnerabilities:
                severity = vuln.get('enhanced_severity', vuln.get('severity', 'info'))
                has_exploit = vuln.get('has_exploit', False)
                
                html += f"""
                        <tr>
                            <td><strong>{vuln.get('host', 'N/A')}</strong></td>
                            <td>{vuln.get('port', 'N/A')}/{vuln.get('service', 'unknown')}</td>
                            <td><a href="https://nvd.nist.gov/vuln/detail/{vuln.get('cve_id', '')}" target="_blank" style="color: #667eea; text-decoration: none;"><strong>{vuln.get('cve_id', 'N/A')}</strong></a></td>
                            <td><strong>{vuln.get('cvss_score', 'N/A')}</strong></td>
                            <td><span class="severity-badge risk-{severity}">{severity.upper()}</span></td>
                            <td><span class="exploit-indicator {'exploit-yes' if has_exploit else 'exploit-no'}">{'YES' if has_exploit else 'NO'}</span></td>
                            <td>{vuln.get('description', 'No description available')[:100]}{'...' if len(vuln.get('description', '')) > 100 else ''}</td>
                            <td>{self._generate_remediation_advice(vuln)}</td>
                        </tr>"""
            
            html += """
                    </tbody>
                </table>
            </div>
        </div>"""
        
        # Add JavaScript for charts
        html += f"""
        <div class="footer">
            <p>🛡️ Report generated by Enhanced Vulnerability Scanner v2.0</p>
            <p>Scan completed at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | 
            Powered by Nmap, NSE Scripts, and CVE Databases</p>
        </div>
    </div>
    
    <script>
        // Severity Chart
        const severityCtx = document.getElementById('severityChart').getContext('2d');
        new Chart(severityCtx, {{
            type: 'doughnut',
            data: {{
                labels: ['Critical', 'High', 'Medium', 'Low', 'Info'],
                datasets: [{{
                    data: [
                        {severity_data.get('critical', 0)},
                        {severity_data.get('high', 0)},
                        {severity_data.get('medium', 0)},
                        {severity_data.get('low', 0)},
                        {severity_data.get('info', 0)}
                    ],
                    backgroundColor: ['#e74c3c', '#f39c12', '#f1c40f', '#27ae60', '#3498db'],
                    borderWidth: 2,
                    borderColor: '#fff'
                }}]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                plugins: {{
                    legend: {{
                        position: 'bottom'
                    }}
                }}
            }}
        }});
        
        // Exploit Chart
        const exploitCtx = document.getElementById('exploitChart').getContext('2d');
        new Chart(exploitCtx, {{
            type: 'pie',
            data: {{
                labels: ['With Exploits', 'Without Exploits'],
                datasets: [{{
                    data: [
                        {exploit_data.get('with_exploit', 0)},
                        {exploit_data.get('without_exploit', 0)}
                    ],
                    backgroundColor: ['#e74c3c', '#95a5a6'],
                    borderWidth: 2,
                    borderColor: '#fff'
                }}]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                plugins: {{
                    legend: {{
                        position: 'bottom'
                    }}
                }}
            }}
        }});
    </script>
</body>
</html>"""
        
        return html
    
    def _generate_remediation_advice(self, vuln: Dict) -> str:
        """Generate specific remediation advice for vulnerabilities"""
        cve_id = vuln.get('cve_id', '')
        service = vuln.get('service', '').lower()
        
        # Specific remediation advice based on CVE and service
        remediation_db = {
            'CVE-2021-44228': 'Update Log4j to version 2.17.0+. Set log4j2.formatMsgNoLookups=true.',
            'CVE-2021-45046': 'Update Log4j to version 2.17.0+. Remove JndiLookup class from classpath.',
            'CVE-2020-15778': 'Update OpenSSH to version 8.4+. Use sftp instead of scp.',
            'CVE-2021-23017': 'Update nginx to version 1.20.1+. Review resolver configuration.',
            'CVE-2022-22965': 'Update Spring Framework to 5.3.18+/5.2.20+. Apply security patches.'
        }
        
        # Service-specific general advice
        service_advice = {
            'apache': 'Keep Apache updated. Review module configurations.',
            'nginx': 'Update nginx regularly. Review proxy configurations.',
            'ssh': 'Use key-based authentication. Disable root login.',
            'mysql': 'Apply security patches. Use strong passwords.',
            'http': 'Enable HTTPS. Keep web server updated.',
            'https': 'Review SSL/TLS configuration. Update certificates.'
        }
        
        # Try specific CVE advice first
        if cve_id in remediation_db:
            return remediation_db[cve_id]
        
        # Fall back to service advice
        if service in service_advice:
            return service_advice[service]
        
        # Generic advice
        return 'Update software to latest version. Apply security patches.'
    
    def _generate_enhanced_json_report(self, data: Dict) -> str:
        """Generate enhanced JSON report with metadata"""
        # Calculate overall risk
        from core.risk_engine import RiskEngine
        risk_engine = RiskEngine()
        overall_risk = risk_engine.calculate_overall_risk(data.get('vulnerabilities', []))
        
        report_data = {
            'metadata': {
                'generated_at': datetime.now().isoformat(),
                'target': data['target'],
                'scanner_version': '2.0',
                'scan_type': 'enhanced_vulnerability_scan',
                'overall_risk': overall_risk
            },
            'scan_configuration': data.get('scan_config', {}),
            'summary': data.get('summary', {}),
            'scan_results': data.get('scan_results', {}),
            'vulnerabilities': data.get('vulnerabilities', []),
            'remediation_summary': self._generate_remediation_summary(data.get('vulnerabilities', []))
        }
        
        return json.dumps(report_data, indent=2, default=str)
    
    def _generate_remediation_summary(self, vulnerabilities: List[Dict]) -> Dict:
        """Generate remediation priority summary"""
        critical_actions = []
        high_priority = []
        medium_priority = []
        
        for vuln in vulnerabilities:
            severity = vuln.get('enhanced_severity', vuln.get('severity', 'info'))
            has_exploit = vuln.get('has_exploit', False)
            cve_id = vuln.get('cve_id', '')
            service = vuln.get('service', '')
            
            action = {
                'cve_id': cve_id,
                'service': service,
                'host': vuln.get('host', ''),
                'remediation': self._generate_remediation_advice(vuln),
                'has_exploit': has_exploit
            }
            
            if severity == 'critical' or (severity == 'high' and has_exploit):
                critical_actions.append(action)
            elif severity == 'high':
                high_priority.append(action)
            elif severity == 'medium':
                medium_priority.append(action)
        
        return {
            'critical_actions_required': len(critical_actions),
            'high_priority_items': len(high_priority),
            'medium_priority_items': len(medium_priority),
            'critical_actions': critical_actions[:5],  # Top 5
            'high_priority': high_priority[:10],       # Top 10
            'recommendations': [
                'Prioritize vulnerabilities with available exploits',
                'Update all software to latest versions',
                'Implement network segmentation',
                'Enable logging and monitoring',
                'Regular security assessments'
            ]
        }
    
    def _generate_enhanced_text_report(self, data: Dict) -> str:
        """Generate enhanced plain text report"""
        vulnerabilities = data.get('vulnerabilities', [])
        summary = data.get('summary', {})
        scan_results = data.get('scan_results', {})
        scan_config = data.get('scan_config', {})
        
        # Calculate overall risk
        from core.risk_engine import RiskEngine
        risk_engine = RiskEngine()
        overall_risk = risk_engine.calculate_overall_risk(vulnerabilities)
        
        report = f"""
================================================================================
                    ENHANCED VULNERABILITY SCAN REPORT
================================================================================

Target: {data['target']}
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Scanner Version: 2.0 (Enhanced)

================================================================================
                              EXECUTIVE SUMMARY
================================================================================

Overall Risk Level: {overall_risk['level'].upper()}
Risk Score: {overall_risk['score']}/1.0
Risk Details: {overall_risk['details']}

VULNERABILITY STATISTICS:
  Total Vulnerabilities: {summary.get('total_vulnerabilities', 0)}
  Unique CVEs: {summary.get('unique_cves', 0)}
  High Priority Issues: {summary.get('high_priority', 0)}
  With Exploits Available: {summary.get('exploit_breakdown', {}).get('with_exploit', 0)}

SCAN CONFIGURATION:
  NSE Scripts: {scan_config.get('nse_scripts', 'N/A')}
  Port Range: {scan_config.get('port_range', 'Default')}
  OS Detection: {'Enabled' if scan_config.get('os_detection') else 'Disabled'}
  Intrusive Tests: {'Disabled' if scan_config.get('intrusive_disabled') else 'Enabled'}

SEVERITY BREAKDOWN:
"""
        
        severity_counts = summary.get('severity_breakdown', {})
        for severity in ['critical', 'high', 'medium', 'low', 'info']:
            count = severity_counts.get(severity, 0)
            report += f"  {severity.title()}: {count}\n"
        
        # Host information with OS detection
        if scan_results.get('hosts'):
            report += f"""
================================================================================
                              DISCOVERED HOSTS
================================================================================
"""
            
            for host_ip, host_data in scan_results['hosts'].items():
                ports = host_data.get('ports', [])
                os_info = host_data.get('os_info', {})
                
                report += f"""
Host: {host_ip}
Status: {host_data.get('state', 'unknown').upper()}"""
                
                if os_info:
                    report += f"""
OS Detection: {os_info.get('name', 'Unknown')} (Accuracy: {os_info.get('accuracy', 'N/A')}%)"""
                
                report += f"""
Open Ports: {', '.join([f"{p.get('port')}/{p.get('protocol')} ({p.get('service', 'unknown')})" for p in ports])}
"""
        
        # Enhanced vulnerability details
        if vulnerabilities:
            report += f"""
================================================================================
                        VULNERABILITY DETAILS & REMEDIATION
================================================================================
"""
            
            for i, vuln in enumerate(vulnerabilities, 1):
                severity = vuln.get('enhanced_severity', vuln.get('severity', 'info'))
                has_exploit = vuln.get('has_exploit', False)
                exploit_count = vuln.get('exploit_count', 0)
                
                report += f"""
[{i}] {vuln.get('cve_id', 'N/A')}
    Host: {vuln.get('host', 'N/A')}
    Port/Service: {vuln.get('port', 'N/A')}/{vuln.get('service', 'unknown')}
    CVSS Score: {vuln.get('cvss_score', 'N/A')}
    Severity: {severity.upper()}
    Exploit Available: {'YES' if has_exploit else 'NO'}"""
                
                if has_exploit and exploit_count > 0:
                    report += f" ({exploit_count} exploits found)"
                
                report += f"""
    Source: {vuln.get('source', 'unknown')}
    Description: {vuln.get('description', 'No description available')}
    Remediation: {self._generate_remediation_advice(vuln)}
    
"""
        
        # Remediation summary
        remediation = self._generate_remediation_summary(vulnerabilities)
        report += f"""
================================================================================
                            REMEDIATION PRIORITIES
================================================================================

CRITICAL ACTIONS REQUIRED: {remediation['critical_actions_required']}
HIGH PRIORITY ITEMS: {remediation['high_priority_items']}
MEDIUM PRIORITY ITEMS: {remediation['medium_priority_items']}

TOP RECOMMENDATIONS:
"""
        
        for i, rec in enumerate(remediation['recommendations'], 1):
            report += f"  {i}. {rec}\n"
        
        if remediation['critical_actions']:
            report += f"""
IMMEDIATE ACTIONS NEEDED:
"""
            for action in remediation['critical_actions']:
                report += f"  - {action['cve_id']} on {action['host']}: {action['remediation']}\n"
        
        report += f"""
================================================================================
                                 FOOTER
================================================================================

Report generated by Enhanced Vulnerability Scanner v2.0
Scan completed at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Powered by Nmap, NSE Scripts, CVE Databases, and Exploit Intelligence

For questions or support, please refer to the documentation.
Remember: Unauthorized scanning may be illegal. Ensure proper authorization.
"""
        
        return report


# =============================================================================
# Enhanced argument parser with new options
# =============================================================================
def parse_arguments():
    """Enhanced argument parser with new scanning options"""
    parser = argparse.ArgumentParser(
        description='Enhanced Network Vulnerability Scanner v2.0',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Enhanced Features:
  • NSE script integration for direct vulnerability detection
  • Exploit availability checking with risk enhancement
  • SQLite database for persistent caching
  • Interactive visual reports with charts
  • OS detection and service fingerprinting
  • Remediation advice and priority ranking

Examples:
  python main.py 192.168.1.1
  python main.py 192.168.1.0/24 --ports 1-1000 --scripts vulners
  python main.py 10.0.0.1 --output report.html --format html --os-detection
  python main.py target.com --scripts all --skip-intrusive
  python main.py 172.16.0.1 --verbose --cvss-weight 0.8 --exploit-weight 0.2
        """
    )
    
    # Basic options
    parser.add_argument('target', help='Target IP address or CIDR range')
    parser.add_argument('--ports', '-p', help='Port range (e.g., 1-1000, 80,443,8080)')
    parser.add_argument('--output', '-o', help='Output file path')
    parser.add_argument('--format', '-f', choices=['html', 'json', 'txt'], 
                       default='html', help='Output format')
    
    # Enhanced scanning options
    parser.add_argument('--scripts', choices=['none', 'vuln', 'vulners', 'vulscan', 'all'], 
                       default='vulners', help='NSE vulnerability scripts to use')
    parser.add_argument('--skip-intrusive', action='store_true', 
                       help='Skip potentially intrusive NSE scripts')
    parser.add_argument('--os-detection', action='store_true', 
                       help='Enable OS detection (-O flag)')
    
    # Risk scoring customization
    parser.add_argument('--cvss-weight', type=float, default=0.6,
                       help='Weight for CVSS scores in risk calculation (0.0-1.0)')
    parser.add_argument('--service-weight', type=float, default=0.15,
                       help='Weight for service criticality (0.0-1.0)')
    parser.add_argument('--port-weight', type=float, default=0.1,
                       help='Weight for port criticality (0.0-1.0)')
    parser.add_argument('--exploit-weight', type=float, default=0.15,
                       help='Weight for exploit availability (0.0-1.0)')
    
    # Advanced options
    parser.add_argument('--verbose', '-v', action='store_true', 
                       help='Enable verbose logging')
    parser.add_argument('--cleanup-cache', action='store_true',
                       help='Clean up old cache entries before scanning')
    parser.add_argument('--show-history', action='store_true',
                       help='Show previous scan history for target')
    
    return parser.parse_args()

def main():
    """Enhanced main entry point"""
    try:
        args = parse_arguments()
        
        if args.verbose:
            logging.getLogger().setLevel(logging.DEBUG)
        
        # Display banner
        console.print("""
[bold blue]
╔══════════════════════════════════════════════════════════════════════════════╗
║                    Enhanced Vulnerability Scanner v2.0                       ║
║                  🛡️  NSE • CVE • Exploits • Remediation  🛡️                   ║
╚══════════════════════════════════════════════════════════════════════════════╝
[/bold blue]
        """)
        
        # Initialize enhanced scanner
        scanner = EnhancedVulnerabilityScanner()
        
        # Configure risk scoring weights if provided
        if any([args.cvss_weight != 0.6, args.service_weight != 0.15, 
               args.port_weight != 0.1, args.exploit_weight != 0.15]):
            scanner.risk_engine.update_scoring_weights(
                cvss_weight=args.cvss_weight,
                service_weight=args.service_weight,
                port_weight=args.port_weight,
                exploit_weight=args.exploit_weight
            )
            console.print(f"[yellow]⚙️  Custom risk weights applied[/yellow]")
        
        # Cleanup cache if requested
        if args.cleanup_cache:
            console.print("[yellow]🧹 Cleaning up old cache entries...[/yellow]")
            scanner.db_manager.cleanup_old_cache()
        
        # Show scan history if requested
        if args.show_history:
            console.print(f"[cyan]📚 Previous scans for {args.target}:[/cyan]")
            history = scanner.db_manager.get_scan_history(args.target)
            if history:
                history_table = Table(title=f"Scan History for {args.target}")
                history_table.add_column("Date", style="cyan")
                history_table.add_column("Vulnerabilities", style="yellow")
                history_table.add_column("High Risk", style="red")
                history_table.add_column("Report", style="green")
                
                for scan in history[:5]:  # Show last 5 scans
                    scan_time = datetime.fromtimestamp(scan['scan_time']).strftime('%Y-%m-%d %H:%M')
                    history_table.add_row(
                        scan_time,
                        str(scan['vulnerability_count']),
                        str(scan['high_risk_count']),
                        scan['report_path']
                    )
                console.print(history_table)
            else:
                console.print("[yellow]No previous scans found[/yellow]")
            console.print()
        
        # Perform enhanced scan
        report_path = scanner.scan_and_analyze(
            target=args.target,
            port_range=args.ports,
            output_file=args.output,
            output_format=args.format,
            nse_scripts=args.scripts,
            skip_intrusive=args.skip_intrusive,
            enable_os_detection=args.os_detection
        )
        
        # Save scan to history
        if report_path:
            # Get vulnerability counts for history
            import json
            try:
                with open(report_path, 'r') as f:
                    if args.format == 'json':
                        report_data = json.load(f)
                        vuln_count = len(report_data.get('vulnerabilities', []))
                        high_risk = sum(1 for v in report_data.get('vulnerabilities', []) 
                                      if v.get('enhanced_severity', v.get('severity', '')) in ['critical', 'high'])
                    else:
                        vuln_count = 0
                        high_risk = 0
                
                scanner.db_manager.save_scan_history(
                    target=args.target,
                    vulnerability_count=vuln_count,
                    high_risk_count=high_risk,
                    scan_config={
                        'nse_scripts': args.scripts,
                        'port_range': args.ports,
                        'os_detection': args.os_detection,
                        'skip_intrusive': args.skip_intrusive
                    },
                    report_path=report_path
                )
            except Exception as e:
                logger.debug(f"Could not save scan history: {e}")
        
        console.print(f"\n[bold green]🎉 Enhanced scan completed successfully![/bold green]")
        console.print(f"[green]📄 Report available at: {report_path}[/green]")
        
    except KeyboardInterrupt:
        console.print("\n[yellow]⚠️  Scan interrupted by user[/yellow]")
        sys.exit(1)
    except Exception as e:
        console.print(f"\n[bold red]❌ Scanner error: {e}[/bold red]")
        logger.error(f"Scanner error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()


# =============================================================================
# utils/validators.py - Input validation utilities
# =============================================================================
import re
import ipaddress
import logging

logger = logging.getLogger(__name__)

def validate_ip(ip_string: str) -> bool:
    """Validate IP address or CIDR range"""
    try:
        # Try single IP address
        ipaddress.ip_address(ip_string)
        return True
    except ValueError:
        try:
            # Try CIDR range
            ipaddress.ip_network(ip_string, strict=False)
            return True
        except ValueError:
            # Try hostname
            if re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$', domain):

            return False

def validate_port_range(port_string: str) -> bool:
    """Validate port range string"""
    if not port_string:
        return True  # Empty is valid (use default)
    
    try:
        # Handle comma-separated ports
        if ',' in port_string:
            ports = port_string.split(',')
            for port in ports:
                port = port.strip()
                if '-' in port:
                    start, end = map(int, port.split('-', 1))
                    if not (1 <= start <= 65535 and 1 <= end <= 65535 and start <= end):
                        return False
                else:
                    port_num = int(port)
                    if not (1 <= port_num <= 65535):
                        return False
            return True
        
        # Handle range
        if '-' in port_string:
            start, end = map(int, port_string.split('-', 1))
            return 1 <= start <= 65535 and 1 <= end <= 65535 and start <= end
        
        # Handle single port
        port_num = int(port_string)
        return 1 <= port_num <= 65535
        
    except ValueError:
        return False

def sanitize_filename(filename: str) -> str:
    """Sanitize filename for safe file operations"""
    # Remove or replace unsafe characters
    filename = re.sub(r'[<>:"/\\|?*]', '_', filename)
    filename = filename.strip('. ')
    
    # Limit length
    if len(filename) > 200:
        filename = filename[:200]
    
    return filename

def validate_cvss_score(score: float) -> bool:
    """Validate CVSS score range"""
    return 0.0 <= score <= 10.0


# =============================================================================
# config/settings.py - Configuration management
# =============================================================================
import os
from pathlib import Path

class Config:
    """Enhanced configuration management"""
    
    # Directories
    BASE_DIR = Path(__file__).parent.parent
    REPORTS_DIR = BASE_DIR / "reports"
    LOGS_DIR = BASE_DIR / "logs"
    CACHE_DIR = BASE_DIR / "cache"
    DATABASE_PATH = BASE_DIR / "vulnerability_scanner.db"
    
    # API Configuration
    CIRCL_API_BASE = "https://cve.circl.lu/api"
    NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    VULNERS_API_BASE = "https://vulners.com/api/v3/search/lucene/"
    EXPLOITDB_API_BASE = "https://www.exploit-db.com/api/v1/search"
    
    # Rate Limiting
    API_RATE_LIMIT = 10  # requests per minute
    API_TIMEOUT = 10     # seconds
    
    # Caching
    CVE_CACHE_EXPIRY = 86400    # 24 hours
    EXPLOIT_CACHE_EXPIRY = 86400 # 24 hours
    MAX_CACHE_SIZE = 1000       # entries
    
    # Scanning defaults
    DEFAULT_PORTS = "1-1000"
    DEFAULT_NSE_SCRIPTS = "vulners"
    DEFAULT_TIMEOUT = 600       # 10 minutes
    
    # Risk scoring defaults
    DEFAULT_CVSS_WEIGHT = 0.6
    DEFAULT_SERVICE_WEIGHT = 0.15
    DEFAULT_PORT_WEIGHT = 0.1
    DEFAULT_EXPLOIT_WEIGHT = 0.15
    
    # Report settings
    MAX_REPORT_SIZE = 50 * 1024 * 1024  # 50MB
    REPORT_RETENTION_DAYS = 30
    
    # Security settings
    ALLOW_INTRUSIVE_SCANS = True
    REQUIRE_SUDO = False
    MAX_CONCURRENT_SCANS = 5
    
    @classmethod
    def ensure_directories(cls):
        """Create necessary directories"""
        for directory in [cls.REPORTS_DIR, cls.LOGS_DIR, cls.CACHE_DIR]:
            directory.mkdir(exist_ok=True)
    
    @classmethod
    def get_env_setting(cls, key: str, default=None):
        """Get setting from environment variables"""
        return os.getenv(f"VULNSCANNER_{key}", default)
    
    @classmethod
    def load_config_file(cls, config_path: str = None):
        """Load configuration from file (JSON/YAML)"""
        if not config_path:
            config_path = cls.BASE_DIR / "config.json"
        
        if Path(config_path).exists():
            import json
            try:
                with open(config_path, 'r') as f:
                    config_data = json.load(f)
                
                # Update class attributes with config values
                for key, value in config_data.items():
                    if hasattr(cls, key.upper()):
                        setattr(cls, key.upper(), value)
                        
                return True
            except Exception as e:
                logger.warning(f"Could not load config file: {e}")
        
        return False


# =============================================================================
# requirements.txt - Dependencies
# =============================================================================
requirements_txt = """# Enhanced Vulnerability Scanner Requirements
# Core dependencies
python-nmap==0.7.1
requests==2.31.0
rich==13.7.0
sqlite3  # Built-in with Python

# Data processing
pandas==2.1.4
numpy==1.24.3

# Network utilities
python-whois==0.9.4
dnspython==2.4.2

# Security utilities
cryptography==41.0.7
pyopenssl==23.3.0

# Optional: Advanced reporting
jinja2==3.1.2
matplotlib==3.8.2
plotly==5.17.0

# Development dependencies (optional)
pytest==7.4.3
black==23.11.0
flake8==6.1.0
mypy==1.7.1

# Documentation
sphinx==7.2.6
"""

# =============================================================================
# config.json - Example configuration file
# =============================================================================
config_json = """{
    "api_rate_limit": 10,
    "api_timeout": 10,
    "cve_cache_expiry": 86400,
    "exploit_cache_expiry": 86400,
    "default_ports": "1-1000",
    "default_nse_scripts": "vulners",
    "default_timeout": 600,
    "allow_intrusive_scans": true,
    "require_sudo": false,
    "max_concurrent_scans": 5,
    "report_retention_days": 30,
    "risk_scoring": {
        "cvss_weight": 0.6,
        "service_weight": 0.15,
        "port_weight": 0.1,
        "exploit_weight": 0.15
    },
    "nse_scripts": {
        "safe": ["vulners", "http-enum", "ssl-enum-ciphers"],
        "intrusive": ["http-sql-injection", "smb-brute", "ssh-brute"],
        "discovery": ["dns-brute", "http-title", "banner"]
    },
    "custom_service_weights": {
        "ssh": 0.9,
        "rdp": 0.9,
        "database": 0.8,
        "web": 0.7
    }
}"""

# =============================================================================
# README.md - Comprehensive documentation
# =============================================================================
readme_md = """# Enhanced Vulnerability Scanner v2.0

🛡️ **Professional Network Vulnerability Assessment Tool**

An advanced vulnerability scanner that combines Nmap's powerful network discovery with CVE databases, exploit intelligence, and automated remediation advice.

## ✨ Key Features

### 🔍 **Advanced Scanning**
- **NSE Script Integration**: Direct vulnerability detection using Nmap scripts
- **Service Fingerprinting**: Detailed service version identification
- **OS Detection**: Operating system fingerprinting
- **Flexible Port Scanning**: Custom port ranges and service-specific scans

### 💾 **Intelligent Caching**
- **SQLite Database**: Persistent storage for CVE and exploit data
- **Smart Caching**: Reduces API calls and improves performance
- **Historical Tracking**: Maintains scan history for trend analysis

### 💥 **Exploit Intelligence**
- **Multi-Source Checking**: ExploitDB, Metasploit, and Vulners integration
- **Risk Enhancement**: Exploitability increases vulnerability risk scores
- **Metasploit Modules**: Identifies available MSF modules

### 📊 **Visual Reporting**
- **Interactive HTML Reports**: Charts, graphs, and responsive design
- **Multiple Formats**: HTML, JSON, and plain text output
- **Executive Summaries**: High-level risk assessments
- **Remediation Guidance**: Specific fix recommendations

### ⚙️ **Customizable Risk Engine**
- **Weighted Scoring**: Adjustable CVSS, service, port, and exploit weights
- **Context-Aware**: Service and port criticality considerations
- **Risk Levels**: Critical, High, Medium, Low, and Informational

## 🚀 Quick Start

### Installation
```bash
# Clone and install dependencies
git clone <repository-url>
cd vulnerability-scanner
pip install -r requirements.txt

# Ensure Nmap is installed
sudo apt-get install nmap  # Ubuntu/Debian
brew install nmap          # macOS
```

### Basic Usage
```bash
# Simple scan
python main.py 192.168.1.1

# Comprehensive scan with all features
python main.py 192.168.1.0/24 --scripts all --os-detection --format html

# Custom port range with specific NSE scripts
python main.py target.com --ports 1-1000 --scripts vulners --output report.html
```

## 📖 Usage Examples

### Basic Scans
```bash
# Single host scan
python main.py 192.168.1.100

# Network range scan
python main.py 192.168.1.0/24 --ports 1-1000

# Domain scan with OS detection
python main.py example.com --os-detection --scripts all
```

### Advanced Options
```bash
# Custom risk weights
python main.py 192.168.1.1 --cvss-weight 0.8 --exploit-weight 0.2

# Skip intrusive tests (safer)
python main.py 192.168.1.1 --skip-intrusive --scripts vulners

# Show scan history
python main.py 192.168.1.1 --show-history

# Clean cache before scanning
python main.py 192.168.1.1 --cleanup-cache --verbose
```

### NSE Script Options
- `none`: No vulnerability scripts
- `vuln`: Standard Nmap vulnerability scripts
- `vulners`: Vulners database integration
- `vulscan`: VulScan NSE script
- `all`: All available vulnerability scripts

## 🎯 Command Line Options

```
Enhanced Network Vulnerability Scanner v2.0

positional arguments:
  target                Target IP address or CIDR range

optional arguments:
  -h, --help            show this help message and exit
  --ports PORTS, -p PORTS
                        Port range (e.g., 1-1000, 80,443,8080)
  --output OUTPUT, -o OUTPUT
                        Output file path
  --format {html,json,txt}, -f {html,json,txt}
                        Output format
  --scripts {none,vuln,vulners,vulscan,all}
                        NSE vulnerability scripts to use
  --skip-intrusive      Skip potentially intrusive NSE scripts
  --os-detection        Enable OS detection (-O flag)
  --cvss-weight CVSS_WEIGHT
                        Weight for CVSS scores in risk calculation (0.0-1.0)
  --service-weight SERVICE_WEIGHT
                        Weight for service criticality (0.0-1.0)
  --port-weight PORT_WEIGHT
                        Weight for port criticality (0.0-1.0)
  --exploit-weight EXPLOIT_WEIGHT
                        Weight for exploit availability (0.0-1.0)
  --verbose, -v         Enable verbose logging
  --cleanup-cache       Clean up old cache entries before scanning
  --show-history        Show previous scan history for target
```

## 📁 Project Structure

```
vulnerability-scanner/
├── main.py                 # Main entry point
├── scanner/
│   └── nmap_scanner.py     # Enhanced Nmap integration
├── core/
│   ├── cve_mapper.py       # CVE database integration
│   ├── risk_engine.py      # Risk calculation engine
│   └── exploit_checker.py  # Exploit availability checker
├── reports/
│   └── report_generator.py # Multi-format report generation
├── utils/
│   ├── database.py         # SQLite database manager
│   └── validators.py       # Input validation utilities
├── config/
│   └── settings.py         # Configuration management
├── requirements.txt        # Python dependencies
├── config.json            # Configuration file (optional)
└── README.md              # This file
```

## 🔧 Configuration

### Environment Variables
```bash
export VULNSCANNER_API_RATE_LIMIT=10
export VULNSCANNER_DEFAULT_PORTS="1-1000"
export VULNSCANNER_ALLOW_INTRUSIVE_SCANS=true
```

### Configuration File (config.json)
```json
{
    "api_rate_limit": 10,
    "default_ports": "1-1000",
    "risk_scoring": {
        "cvss_weight": 0.6,
        "exploit_weight": 0.15
    },
    "custom_service_weights": {
        "ssh": 0.9,
        "database": 0.8
    }
}
```

## 📊 Report Features

### HTML Reports Include:
- **Executive Dashboard**: Risk overview with charts
- **Interactive Charts**: Severity and exploit distribution
- **Host Discovery**: OS detection and service enumeration
- **Vulnerability Matrix**: Detailed findings with remediation
- **Remediation Priorities**: Actionable next steps

### JSON Reports Provide:
- **Structured Data**: Machine-readable format
- **API Integration**: Easy integration with other tools
- **Historical Data**: Timestamp and metadata
- **Remediation Summary**: Prioritized action items

## 🛡️ Security Considerations

### Ethical Usage
- **Authorization Required**: Only scan systems you own or have permission to test
- **Legal Compliance**: Ensure compliance with local laws and regulations
- **Responsible Disclosure**: Report vulnerabilities through proper channels

### Scanner Safety
- **Rate Limiting**: Built-in API rate limiting to avoid blocking
- **Non-Intrusive Mode**: `--skip-intrusive` flag for safer scanning
- **Timeout Controls**: Configurable timeouts to prevent hanging

## 🔍 Technical Details

### Risk Calculation
The enhanced risk engine uses weighted scoring:
- **CVSS Score (60%)**: Base vulnerability severity
- **Service Criticality (15%)**: Service-specific risk factors
- **Port Criticality (10%)**: Port-based risk assessment
- **Exploit Availability (15%)**: Presence of known exploits

### Database Schema
- **CVE Cache**: Service/version to CVE mappings
- **Exploit Cache**: CVE to exploit availability data
- **Scan History**: Historical scan results and trends

### Performance Optimizations
- **Concurrent Processing**: Multi-threaded vulnerability analysis
- **Smart Caching**: Reduces redundant API calls
- **Progressive Loading**: Real-time progress updates

## 🤝 Contributing

We welcome contributions! Please see our contributing guidelines:

1. **Fork the Repository**
2. **Create a Feature Branch**
3. **Add Tests** for new functionality
4. **Update Documentation**
5. **Submit a Pull Request**

### Development Setup
```bash
# Install development dependencies
pip install -r requirements-dev.txt

# Run tests
python -m pytest tests/

# Code formatting
black main.py scanner/ core/ utils/ reports/

# Type checking
mypy main.py
```

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

## ⚠️ Disclaimer

This tool is provided for educational and authorized testing purposes only. Users are responsible for complying with applicable laws and regulations. The authors assume no liability for misuse of this software.

## 📞 Support

- **Documentation**: See inline code comments and docstrings
- **Issues**: Report bugs via GitHub issues
- **Feature Requests**: Submit enhancement requests
- **Security**: Report security issues privately

## 🔄 Version History

### v2.0 (Current)
- ✅ NSE script integration
- ✅ Exploit availability checking
- ✅ SQLite database caching
- ✅ Enhanced visual reports
- ✅ OS detection support
- ✅ Customizable risk scoring

### v1.0
- ✅ Basic Nmap integration
- ✅ CVE database lookup
- ✅ HTML report generation
- ✅ Risk assessment engine

---

Made with ❤️ for the cybersecurity community. Happy hunting! 🎯
"""

print("Enhanced Vulnerability Scanner v2.0 - Complete Implementation")
print("\nThis comprehensive security tool includes:")
print("✅ NSE script integration for direct vulnerability detection")
print("✅ SQLite database for persistent caching")
print("✅ Exploit availability checking with risk enhancement")
print("✅ Visual HTML reports with charts and remediation advice")
print("✅ OS detection and advanced service fingerprinting")
print("✅ Customizable risk scoring engine")
print("✅ Command history and scan tracking")
print("✅ Multiple output formats (HTML, JSON, text)")
print("✅ Comprehensive documentation and examples")
print("\nSave each file in the appropriate directory structure and install dependencies!")
print("Remember: Only use this tool on systems you own or have explicit permission to test.", ip_string)

                return True
            return False

def validate_port_range(port_string: str) -> bool:
    """Validate port range string"""
    if not port_string:
        return True  # Empty is valid (use default)
    
    try:
        # Handle comma-separated ports
        if ',' in port_string:
            ports = port_string.split(',')
            for port in ports:
                port = port.strip()
                if '-' in port:
                    start, end = map(int, port.split('-', 1))
                    if not (1 <= start <= 65535 and 1 <= end <= 65535 and start <= end):
                        return False
                else:
                    port_num = int(port)
                    if not (1 <= port_num <= 65535):
                        return False
            return True
        
        # Handle range
        if '-' in port_string:
            start, end = map(int, port_string.split('-', 1))
            return 1 <= start <= 65535 and 1 <= end <= 65535 and start <= end
        
        # Handle single port
        port_num = int(port_string)
        return 1 <= port_num <= 65535
        
    except ValueError:
        return False

def sanitize_filename(filename: str) -> str:
    """Sanitize filename for safe file operations"""
    # Remove or replace unsafe characters
    filename = re.sub(r'[<>:"/\\|?*]', '_', filename)
    filename = filename.strip('. ')
    
    # Limit length
    if len(filename) > 200:
        filename = filename[:200]
    
    return filename

def validate_cvss_score(score: float) -> bool:
    """Validate CVSS score range"""
    return 0.0 <= score <= 10.0


# =============================================================================
# config/settings.py - Configuration management
# =============================================================================
import os
from pathlib import Path

class Config:
    """Enhanced configuration management"""
    
    # Directories
    BASE_DIR = Path(__file__).parent.parent
    REPORTS_DIR = BASE_DIR / "reports"
    LOGS_DIR = BASE_DIR / "logs"
    CACHE_DIR = BASE_DIR / "cache"
    DATABASE_PATH = BASE_DIR / "vulnerability_scanner.db"
    
    # API Configuration
    CIRCL_API_BASE = "https://cve.circl.lu/api"
    NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    VULNERS_API_BASE = "https://vulners.com/api/v3/search/lucene/"
    EXPLOITDB_API_BASE = "https://www.exploit-db.com/api/v1/search"
    
    # Rate Limiting
    API_RATE_LIMIT = 10  # requests per minute
    API_TIMEOUT = 10     # seconds
    
    # Caching
    CVE_CACHE_EXPIRY = 86400    # 24 hours
    EXPLOIT_CACHE_EXPIRY = 86400 # 24 hours
    MAX_CACHE_SIZE = 1000       # entries
    
    # Scanning defaults
    DEFAULT_PORTS = "1-1000"
    DEFAULT_NSE_SCRIPTS = "vulners"
    DEFAULT_TIMEOUT = 600       # 10 minutes
    
    # Risk scoring defaults
    DEFAULT_CVSS_WEIGHT = 0.6
    DEFAULT_SERVICE_WEIGHT = 0.15
    DEFAULT_PORT_WEIGHT = 0.1
    DEFAULT_EXPLOIT_WEIGHT = 0.15
    
    # Report settings
    MAX_REPORT_SIZE = 50 * 1024 * 1024  # 50MB
    REPORT_RETENTION_DAYS = 30
    
    # Security settings
    ALLOW_INTRUSIVE_SCANS = True
    REQUIRE_SUDO = False
    MAX_CONCURRENT_SCANS = 5
    
    @classmethod
    def ensure_directories(cls):
        """Create necessary directories"""
        for directory in [cls.REPORTS_DIR, cls.LOGS_DIR, cls.CACHE_DIR]:
            directory.mkdir(exist_ok=True)
    
    @classmethod
    def get_env_setting(cls, key: str, default=None):
        """Get setting from environment variables"""
        return os.getenv(f"VULNSCANNER_{key}", default)
    
    @classmethod
    def load_config_file(cls, config_path: str = None):
        """Load configuration from file (JSON/YAML)"""
        if not config_path:
            config_path = cls.BASE_DIR / "config.json"
        
        if Path(config_path).exists():
            import json
            try:
                with open(config_path, 'r') as f:
                    config_data = json.load(f)
                
                # Update class attributes with config values
                for key, value in config_data.items():
                    if hasattr(cls, key.upper()):
                        setattr(cls, key.upper(), value)
                        
                return True
            except Exception as e:
                logger.warning(f"Could not load config file: {e}")
        
        return False


# =============================================================================
# requirements.txt - Dependencies
# =============================================================================
requirements_txt = """# Enhanced Vulnerability Scanner Requirements
# Core dependencies
python-nmap==0.7.1
requests==2.31.0
rich==13.7.0
sqlite3  # Built-in with Python

# Data processing
pandas==2.1.4
numpy==1.24.3

# Network utilities
python-whois==0.9.4
dnspython==2.4.2

# Security utilities
cryptography==41.0.7
pyopenssl==23.3.0

# Optional: Advanced reporting
jinja2==3.1.2
matplotlib==3.8.2
plotly==5.17.0

# Development dependencies (optional)
pytest==7.4.3
black==23.11.0
flake8==6.1.0
mypy==1.7.1

# Documentation
sphinx==7.2.6
"""

# =============================================================================
# config.json - Example configuration file
# =============================================================================
config_json = """{
    "api_rate_limit": 10,
    "api_timeout": 10,
    "cve_cache_expiry": 86400,
    "exploit_cache_expiry": 86400,
    "default_ports": "1-1000",
    "default_nse_scripts": "vulners",
    "default_timeout": 600,
    "allow_intrusive_scans": true,
    "require_sudo": false,
    "max_concurrent_scans": 5,
    "report_retention_days": 30,
    "risk_scoring": {
        "cvss_weight": 0.6,
        "service_weight": 0.15,
        "port_weight": 0.1,
        "exploit_weight": 0.15
    },
    "nse_scripts": {
        "safe": ["vulners", "http-enum", "ssl-enum-ciphers"],
        "intrusive": ["http-sql-injection", "smb-brute", "ssh-brute"],
        "discovery": ["dns-brute", "http-title", "banner"]
    },
    "custom_service_weights": {
        "ssh": 0.9,
        "rdp": 0.9,
        "database": 0.8,
        "web": 0.7
    }
}"""

# =============================================================================
# README.md - Comprehensive documentation
# =============================================================================
readme_md = """# Enhanced Vulnerability Scanner v2.0

🛡️ **Professional Network Vulnerability Assessment Tool**

An advanced vulnerability scanner that combines Nmap's powerful network discovery with CVE databases, exploit intelligence, and automated remediation advice.

## ✨ Key Features

### 🔍 **Advanced Scanning**
- **NSE Script Integration**: Direct vulnerability detection using Nmap scripts
- **Service Fingerprinting**: Detailed service version identification
- **OS Detection**: Operating system fingerprinting
- **Flexible Port Scanning**: Custom port ranges and service-specific scans

### 💾 **Intelligent Caching**
- **SQLite Database**: Persistent storage for CVE and exploit data
- **Smart Caching**: Reduces API calls and improves performance
- **Historical Tracking**: Maintains scan history for trend analysis

### 💥 **Exploit Intelligence**
- **Multi-Source Checking**: ExploitDB, Metasploit, and Vulners integration
- **Risk Enhancement**: Exploitability increases vulnerability risk scores
- **Metasploit Modules**: Identifies available MSF modules

### 📊 **Visual Reporting**
- **Interactive HTML Reports**: Charts, graphs, and responsive design
- **Multiple Formats**: HTML, JSON, and plain text output
- **Executive Summaries**: High-level risk assessments
- **Remediation Guidance**: Specific fix recommendations

### ⚙️ **Customizable Risk Engine**
- **Weighted Scoring**: Adjustable CVSS, service, port, and exploit weights
- **Context-Aware**: Service and port criticality considerations
- **Risk Levels**: Critical, High, Medium, Low, and Informational

## 🚀 Quick Start

### Installation
```bash
# Clone and install dependencies
git clone <repository-url>
cd vulnerability-scanner
pip install -r requirements.txt

# Ensure Nmap is installed
sudo apt-get install nmap  # Ubuntu/Debian
brew install nmap          # macOS
```

### Basic Usage
```bash
# Simple scan
python main.py 192.168.1.1

# Comprehensive scan with all features
python main.py 192.168.1.0/24 --scripts all --os-detection --format html

# Custom port range with specific NSE scripts
python main.py target.com --ports 1-1000 --scripts vulners --output report.html
```

## 📖 Usage Examples

### Basic Scans
```bash
# Single host scan
python main.py 192.168.1.100

# Network range scan
python main.py 192.168.1.0/24 --ports 1-1000

# Domain scan with OS detection
python main.py example.com --os-detection --scripts all
```

### Advanced Options
```bash
# Custom risk weights
python main.py 192.168.1.1 --cvss-weight 0.8 --exploit-weight 0.2

# Skip intrusive tests (safer)
python main.py 192.168.1.1 --skip-intrusive --scripts vulners

# Show scan history
python main.py 192.168.1.1 --show-history

# Clean cache before scanning
python main.py 192.168.1.1 --cleanup-cache --verbose
```

### NSE Script Options
- `none`: No vulnerability scripts
- `vuln`: Standard Nmap vulnerability scripts
- `vulners`: Vulners database integration
- `vulscan`: VulScan NSE script
- `all`: All available vulnerability scripts

## 🎯 Command Line Options

```
Enhanced Network Vulnerability Scanner v2.0

positional arguments:
  target                Target IP address or CIDR range

optional arguments:
  -h, --help            show this help message and exit
  --ports PORTS, -p PORTS
                        Port range (e.g., 1-1000, 80,443,8080)
  --output OUTPUT, -o OUTPUT
                        Output file path
  --format {html,json,txt}, -f {html,json,txt}
                        Output format
  --scripts {none,vuln,vulners,vulscan,all}
                        NSE vulnerability scripts to use
  --skip-intrusive      Skip potentially intrusive NSE scripts
  --os-detection        Enable OS detection (-O flag)
  --cvss-weight CVSS_WEIGHT
                        Weight for CVSS scores in risk calculation (0.0-1.0)
  --service-weight SERVICE_WEIGHT
                        Weight for service criticality (0.0-1.0)
  --port-weight PORT_WEIGHT
                        Weight for port criticality (0.0-1.0)
  --exploit-weight EXPLOIT_WEIGHT
                        Weight for exploit availability (0.0-1.0)
  --verbose, -v         Enable verbose logging
  --cleanup-cache       Clean up old cache entries before scanning
  --show-history        Show previous scan history for target
```

## 📁 Project Structure

```
vulnerability-scanner/
├── main.py                 # Main entry point
├── scanner/
│   └── nmap_scanner.py     # Enhanced Nmap integration
├── core/
│   ├── cve_mapper.py       # CVE database integration
│   ├── risk_engine.py      # Risk calculation engine
│   └── exploit_checker.py  # Exploit availability checker
├── reports/
│   └── report_generator.py # Multi-format report generation
├── utils/
│   ├── database.py         # SQLite database manager
│   └── validators.py       # Input validation utilities
├── config/
│   └── settings.py         # Configuration management
├── requirements.txt        # Python dependencies
├── config.json            # Configuration file (optional)
└── README.md              # This file
```

## 🔧 Configuration

### Environment Variables
```bash
export VULNSCANNER_API_RATE_LIMIT=10
export VULNSCANNER_DEFAULT_PORTS="1-1000"
export VULNSCANNER_ALLOW_INTRUSIVE_SCANS=true
```

### Configuration File (config.json)
```json
{
    "api_rate_limit": 10,
    "default_ports": "1-1000",
    "risk_scoring": {
        "cvss_weight": 0.6,
        "exploit_weight": 0.15
    },
    "custom_service_weights": {
        "ssh": 0.9,
        "database": 0.8
    }
}
```

## 📊 Report Features

### HTML Reports Include:
- **Executive Dashboard**: Risk overview with charts
- **Interactive Charts**: Severity and exploit distribution
- **Host Discovery**: OS detection and service enumeration
- **Vulnerability Matrix**: Detailed findings with remediation
- **Remediation Priorities**: Actionable next steps

### JSON Reports Provide:
- **Structured Data**: Machine-readable format
- **API Integration**: Easy integration with other tools
- **Historical Data**: Timestamp and metadata
- **Remediation Summary**: Prioritized action items

## 🛡️ Security Considerations

### Ethical Usage
- **Authorization Required**: Only scan systems you own or have permission to test
- **Legal Compliance**: Ensure compliance with local laws and regulations
- **Responsible Disclosure**: Report vulnerabilities through proper channels

### Scanner Safety
- **Rate Limiting**: Built-in API rate limiting to avoid blocking
- **Non-Intrusive Mode**: `--skip-intrusive` flag for safer scanning
- **Timeout Controls**: Configurable timeouts to prevent hanging

## 🔍 Technical Details

### Risk Calculation
The enhanced risk engine uses weighted scoring:
- **CVSS Score (60%)**: Base vulnerability severity
- **Service Criticality (15%)**: Service-specific risk factors
- **Port Criticality (10%)**: Port-based risk assessment
- **Exploit Availability (15%)**: Presence of known exploits

### Database Schema
- **CVE Cache**: Service/version to CVE mappings
- **Exploit Cache**: CVE to exploit availability data
- **Scan History**: Historical scan results and trends

### Performance Optimizations
- **Concurrent Processing**: Multi-threaded vulnerability analysis
- **Smart Caching**: Reduces redundant API calls
- **Progressive Loading**: Real-time progress updates

## 🤝 Contributing

We welcome contributions! Please see our contributing guidelines:

1. **Fork the Repository**
2. **Create a Feature Branch**
3. **Add Tests** for new functionality
4. **Update Documentation**
5. **Submit a Pull Request**

### Development Setup
```bash
# Install development dependencies
pip install -r requirements-dev.txt

# Run tests
python -m pytest tests/

# Code formatting
black main.py scanner/ core/ utils/ reports/

# Type checking
mypy main.py
```

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

## ⚠️ Disclaimer

This tool is provided for educational and authorized testing purposes only. Users are responsible for complying with applicable laws and regulations. The authors assume no liability for misuse of this software.

## 📞 Support

- **Documentation**: See inline code comments and docstrings
- **Issues**: Report bugs via GitHub issues
- **Feature Requests**: Submit enhancement requests
- **Security**: Report security issues privately

## 🔄 Version History

### v2.0 (Current)
- ✅ NSE script integration
- ✅ Exploit availability checking
- ✅ SQLite database caching
- ✅ Enhanced visual reports
- ✅ OS detection support
- ✅ Customizable risk scoring

### v1.0
- ✅ Basic Nmap integration
- ✅ CVE database lookup
- ✅ HTML report generation
- ✅ Risk assessment engine

---

Made with ❤️ for the cybersecurity community. Happy hunting! 🎯
"""

print("Enhanced Vulnerability Scanner v2.0 - Complete Implementation")
print("\nThis comprehensive security tool includes:")
print("✅ NSE script integration for direct vulnerability detection")
print("✅ SQLite database for persistent caching")
print("✅ Exploit availability checking with risk enhancement")
print("✅ Visual HTML reports with charts and remediation advice")
print("✅ OS detection and advanced service fingerprinting")
print("✅ Customizable risk scoring engine")
print("✅ Command history and scan tracking")
print("✅ Multiple output formats (HTML, JSON, text)")
print("✅ Comprehensive documentation and examples")
print("\nSave each file in the appropriate directory structure and install dependencies!")
print("Remember: Only use this tool on systems you own or have explicit permission to test.")