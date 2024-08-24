"""
title: Security and Compliance Diagnostic Toolkit
author: Phil Dougherty
email: pd@suicidebutton.com
date: 2024-08-28
version: 2.0
license: MIT
description: Toolkit for security and compliance diagnostics including SSL checks, port vulnerability scans, subdomain enumeration, and CSP reports.
"""

import ssl
import socket
import requests
import json
import subprocess
from typing import Optional, Callable, Any
from datetime import datetime
from pydantic import BaseModel, Field
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# Suppress only the single InsecureRequestWarning from urllib3 needed for SSL certificate checks
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Logging setup
import logging
logging.basicConfig(level=logging.INFO)

# Input Models
class SSLCheckInput(BaseModel):
    domain: str = Field(..., description="The domain name to check SSL certificate for.")

class PortVulnerabilityScanInput(BaseModel):
    host: str = Field(..., description="The host to scan for open ports.")
    ports: Optional[str] = Field(None, description="Comma-separated list of ports to scan (e.g., '80,443').")

class SubdomainEnumerationInput(BaseModel):
    domain: str = Field(..., description="The domain name to enumerate subdomains for.")

class CSPReportInput(BaseModel):
    domain: str = Field(..., description="The domain name to check Content Security Policy (CSP) for.")

# Event emitter class for handling progress updates
class EventEmitter:
    def __init__(self, event_emitter: Callable[[dict], Any] = None):
        self.event_emitter = event_emitter

    async def progress_update(self, description):
        await self.emit(description)

    async def error_update(self, description):
        await self.emit(description, "error", True)

    async def success_update(self, description):
        await self.emit(description, "success", True)

    async def emit(self, description="Unknown State", status="in_progress", done=False):
        if self.event_emitter:
            await self.event_emitter(
                {
                    "type": "status",
                    "data": {
                        "status": status,
                        "description": description,
                        "done": done,
                    },
                }
            )

# Core Toolkit Class
class SecurityComplianceToolkit:
    def __init__(self):
        pass

    async def ssl_check(self, domain: str, __event_emitter__: Callable[[dict], Any] = None) -> str:
        """
        Check SSL certificate details for a given domain.
        """
        emitter = EventEmitter(__event_emitter__)
        await emitter.progress_update(f"Checking SSL certificate for {domain}...")

        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    ssl_info = {
                        "subject": dict(x[0] for x in cert["subject"]),
                        "issuer": dict(x[0] for x in cert["issuer"]),
                        "notBefore": cert["notBefore"],
                        "notAfter": cert["notAfter"],
                    }
                    await emitter.success_update(f"SSL check for {domain} complete!")
                    return json.dumps(ssl_info)
        except Exception as e:
            await emitter.error_update(f"SSL check error for {domain}: {str(e)}")
            return json.dumps({"error": str(e)})

    async def port_vulnerability_scan(self, host: str, ports: Optional[str] = None, __event_emitter__: Callable[[dict], Any] = None) -> str:
        """
        Perform a port vulnerability scan on a given host.
        """
        emitter = EventEmitter(__event_emitter__)
        await emitter.progress_update(f"Scanning ports for vulnerabilities on {host}...")

        try:
            nmap_args = ["nmap", "-sV", "--script", "vuln", host]
            if ports:
                nmap_args.extend(["-p", ports])

            result = subprocess.check_output(nmap_args, stderr=subprocess.STDOUT).decode('utf-8')
            await emitter.success_update(f"Port vulnerability scan on {host} complete!")
            return result
        except subprocess.CalledProcessError as e:
            await emitter.error_update(f"Error during port vulnerability scan: {e.output.decode('utf-8')}")
            return json.dumps({"error": e.output.decode('utf-8')})

    async def subdomain_enumeration(self, domain: str, __event_emitter__: Callable[[dict], Any] = None) -> str:
        """
        Enumerate subdomains for a given domain.
        """
        emitter = EventEmitter(__event_emitter__)
        await emitter.progress_update(f"Enumerating subdomains for {domain}...")

        try:
            subdomains = []
            # Use Sublist3r or a similar library to enumerate subdomains
            import sublist3r
            subdomains = sublist3r.main(domain, 40, ports=None, silent=True, verbose=False, enable_bruteforce=False, engines=None)
            await emitter.success_update(f"Subdomain enumeration for {domain} complete!")
            return json.dumps({"subdomains": subdomains})
        except Exception as e:
            await emitter.error_update(f"Error during subdomain enumeration: {str(e)}")
            return json.dumps({"error": str(e)})

    async def csp_report(self, domain: str, __event_emitter__: Callable[[dict], Any] = None) -> str:
        """
        Generate a Content Security Policy (CSP) report for a given domain.
        """
        emitter = EventEmitter(__event_emitter__)
        await emitter.progress_update(f"Checking Content Security Policy (CSP) for {domain}...")

        try:
            response = requests.get(f"https://{domain}", verify=False)
            csp = response.headers.get("Content-Security-Policy", "No CSP header found.")
            await emitter.success_update(f"CSP check for {domain} complete!")
            return json.dumps({"CSP": csp})
        except requests.RequestException as e:
            await emitter.error_update(f"Error during CSP check: {str(e)}")
            return json.dumps({"error": str(e)})


# Valves for OpenWebUI Integration
async def ssl_check_valve(args: SSLCheckInput, __event_emitter__: Callable[[dict], Any] = None) -> str:
    toolkit = SecurityComplianceToolkit()
    return await toolkit.ssl_check(args.domain, __event_emitter__)

async def port_vulnerability_scan_valve(args: PortVulnerabilityScanInput, __event_emitter__: Callable[[dict], Any] = None) -> str:
    toolkit = SecurityComplianceToolkit()
    return await toolkit.port_vulnerability_scan(args.host, args.ports, __event_emitter__)

async def subdomain_enumeration_valve(args: SubdomainEnumerationInput, __event_emitter__: Callable[[dict], Any] = None) -> str:
    toolkit = SecurityComplianceToolkit()
    return await toolkit.subdomain_enumeration(args.domain, __event_emitter__)

async def csp_report_valve(args: CSPReportInput, __event_emitter__: Callable[[dict], Any] = None) -> str:
    toolkit = SecurityComplianceToolkit()
    return await toolkit.csp_report(args.domain, __event_emitter__)


# Register pipelines for OpenWebUI
def register_pipelines():
    pipelines = {
        "security_compliance_pipeline": {
            "description": "Pipeline for security and compliance diagnostics including SSL checks, port vulnerability scans, subdomain enumeration, and CSP reports.",
            "valves": {
                "ssl_check": {
                    "description": "Check SSL certificate details for a domain.",
                    "function": "ssl_check_valve",
                    "input_model": "SSLCheckInput"
                },
                "port_vulnerability_scan": {
                    "description": "Scan ports on a host for vulnerabilities using nmap.",
                    "function": "port_vulnerability_scan_valve",
                    "input_model": "PortVulnerabilityScanInput"
                },
                "subdomain_enumeration": {
                    "description": "Enumerate subdomains for a given domain.",
                    "function": "subdomain_enumeration_valve",
                    "input_model": "SubdomainEnumerationInput"
                },
                "csp_report": {
                    "description": "Generate a Content Security Policy (CSP) report for a domain.",
                    "function": "csp_report_valve",
                    "input_model": "CSPReportInput"
                }
            },
            "filters": [],  # Add any filters if necessary
            "pipes": [],  # Add any pipes if necessary
        }
    }
    return pipelines

# This function is called by OpenWebUI to register pipelines
pipelines = register_pipelines()

# --- Example Usage ---
if __name__ == "__main__":
    import asyncio

    async def test_toolkit():
        # SSL Check Example
        ssl_check_result = await ssl_check_valve(SSLCheckInput(domain="google.com"))
        print(f"SSL Check Result: {ssl_check_result}")

        # Port Vulnerability Scan Example
        port_scan_result = await port_vulnerability_scan_valve(PortVulnerabilityScanInput(host="google.com", ports="80,443"))
        print(f"Port Vulnerability Scan Result: {port_scan_result}")

        # Subdomain Enumeration Example
        subdomain_result = await subdomain_enumeration_valve(SubdomainEnumerationInput(domain="google.com"))
        print(f"Subdomain Enumeration Result: {subdomain_result}")

        # CSP Report Example
        csp_result = await csp_report_valve(CSPReportInput(domain="google.com"))
        print(f"CSP Report Result: {csp_result}")

    asyncio.run(test_toolkit())
