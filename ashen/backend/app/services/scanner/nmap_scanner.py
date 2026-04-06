"""
scanner/nmap_scanner.py
Wrapper around subprocess nmap with XML parsing.
P1.5: Uses unique temp files per scan run and guarantees cleanup.
R2: Uses Popen for subprocess tracking; exposes PID for cancellation.
"""
import time
import tempfile
import uuid
import xml.etree.ElementTree as ET
import subprocess
import shutil
import threading
from typing import Dict, Any, Optional
import os


# ── Process registry for cancellation ────────────────────────────────

_proc_lock = threading.Lock()
_active_procs: dict[int, subprocess.Popen] = {}  # scan_id → Popen


def register_scan_process(scan_id: int, proc: subprocess.Popen):
    with _proc_lock:
        _active_procs[scan_id] = proc


def unregister_scan_process(scan_id: int):
    with _proc_lock:
        _active_procs.pop(scan_id, None)


def kill_scan_process(scan_id: int) -> bool:
    """Terminate the nmap subprocess for a given scan. Returns True if killed."""
    with _proc_lock:
        proc = _active_procs.pop(scan_id, None)
    if proc is None:
        return False
    try:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        return True
    except OSError:
        return False


class NmapScanner:
    def __init__(self):
        if not shutil.which("nmap"):
            raise EnvironmentError("nmap is not installed or not in PATH.")

    def quick_scan(
        self,
        target: str,
        args: str = "-sV --script vuln",
        scan_id: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Run nmap with vulnerability scripts and parse XML output.
        Uses a unique temp file per invocation and cleans up after.
        If scan_id is provided, registers the subprocess for cancellation.
        """
        if not target:
            raise ValueError("target is required")

        # P1.5: Unique filename per run to prevent collisions
        scan_dir = os.path.join(tempfile.gettempdir(), "ashen_scans")
        os.makedirs(scan_dir, exist_ok=True)
        unique_id = uuid.uuid4().hex[:12]
        xml_file = os.path.join(scan_dir, f"scan_{unique_id}.xml")

        cmd = ["nmap"] + args.split() + ["-oX", xml_file, target]
        print(f"[*] Running command: {' '.join(cmd)}")
        start = time.time()

        # R2: Use Popen for subprocess tracking instead of run()
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if scan_id is not None:
            register_scan_process(scan_id, proc)

        try:
            _, stderr = proc.communicate(timeout=600)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.communicate()
            self._cleanup(xml_file)
            raise RuntimeError("Nmap scan timed out (Limit: 10 mins)")
        finally:
            if scan_id is not None:
                unregister_scan_process(scan_id)

        duration = time.time() - start

        if proc.returncode != 0:
            self._cleanup(xml_file)
            # returncode -15 = SIGTERM (cancelled), -9 = SIGKILL
            if proc.returncode in (-15, -9):
                raise RuntimeError("Scan was cancelled")
            raise RuntimeError(f"nmap failed: {stderr.decode()}")

        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
        except ET.ParseError as e:
            self._cleanup(xml_file)
            raise RuntimeError(f"Failed to parse Nmap XML: {e}")

        # P1.5: Guaranteed cleanup after successful parse
        self._cleanup(xml_file)

        parsed = {
            'target': target,
            'duration': duration,
            'hosts': []
        }

        for host in root.findall('host'):
            addr = host.find("address")
            ip = addr.get('addr') if addr is not None else 'unknown'

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

    @staticmethod
    def _cleanup(xml_file: str):
        """Remove the temp XML file if it exists."""
        try:
            if os.path.exists(xml_file):
                os.remove(xml_file)
        except OSError:
            pass
