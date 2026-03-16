"""
scanner/nmap_scanner.py
Wrapper around subprocess nmap with XML parsing.
UPDATED: Now parses NSE script outputs to detect vulnerabilities.
"""
import time
import tempfile
import xml.etree.ElementTree as ET
import subprocess
import shutil
from typing import Dict, Any
import os

class NmapScanner:
    def __init__(self):
        # Check if nmap is actually installed
        if not shutil.which("nmap"):
            raise EnvironmentError("nmap is not installed or not in PATH.")

    def quick_scan(self, target: str, args: str = "-sV --script vuln") -> Dict[str, Any]:
        """
        Run nmap with vulnerability scripts and parse XML output.
        """
        if not target:
            raise ValueError("target is required")

        scan_dir = os.path.join(tempfile.gettempdir(), "ashen_scans")
        os.makedirs(scan_dir, exist_ok=True)
        xml_file = os.path.join(scan_dir, f"scan_{target.replace('/', '_').replace('.', '_')}.xml")

        cmd = ["nmap"] + args.split() + ["-oX", xml_file, target]
        print(f"[*] Running command: {' '.join(cmd)}")
        start = time.time()

        # Run Nmap
        try:
            proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=600)
        except subprocess.TimeoutExpired:
            raise RuntimeError("Nmap scan timed out (Limit: 10 mins)")

        duration = time.time() - start

        if proc.returncode != 0:
            raise RuntimeError(f"nmap failed: {proc.stderr.decode()}")

        # Parse XML
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
        except ET.ParseError as e:
            raise RuntimeError(f"Failed to parse Nmap XML: {e}")

        parsed = {
            'target': target,
            'duration': duration,
            'hosts': []
        }

        for host in root.findall('host'):
            # Get IP
            addr = host.find("address")
            ip = addr.get('addr') if addr is not None else 'unknown'

            # Get State
            status = host.find('status')
            state = status.get('state') if status is not None else 'unknown'

            hostinfo = {
                'ip': ip,
                'state': state,
                'protocols': {},
                'vulns': []
            }

            for ports in host.findall('ports'):
                for port in ports.findall('port'):
                    pnum = int(port.get('portid'))
                    proto = port.get('protocol')

                    service = port.find('service')
                    product = service.get('product') if service is not None else ''
                    version = service.get('version') if service is not None else ''
                    name = service.get('name') if service is not None else ''

                    port_entry = {
                        'port': pnum,
                        'state': port.find('state').get('state'),
                        'name': name,
                        'product': product,
                        'version': version,
                        'scripts': {}
                    }

                    # Parse NSE script outputs
                    for script in port.findall('script'):
                        script_id = script.get('id')
                        output = script.get('output')
                        port_entry['scripts'][script_id] = output

                        if "VULNERABLE" in output or "Exploitable" in output:
                            hostinfo['vulns'].append({
                                'port': pnum,
                                'id': script_id,
                                'output': output
                            })

                    if proto not in hostinfo['protocols']:
                        hostinfo['protocols'][proto] = []

                    hostinfo['protocols'][proto].append(port_entry)

            parsed['hosts'].append(hostinfo)

        return parsed
