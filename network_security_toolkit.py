"""
title: Network and Website/Endpoint Security and Compliance Toolkit
author: Phil Dougherty
email: pd@suicidebutton.com
date: 2024-08-24
version: 1.0
license: MIT
description: General tools for network/web/endpoint security diagnostics and testing.
"""

import json
import logging
import requests
import socket
import ssl
from pydantic import BaseModel, Field
from typing import Optional, Callable, Any
from datetime import datetime

logging.basicConfig(level=logging.INFO)

# Input models
class SSLCertificateDetailsInput(BaseModel):
    domain: str = Field(..., description="The domain to fetch SSL certificate details for (e.g., 'google.com').")

class OpenPortScannerInput(BaseModel):
    host: str = Field(..., description="The host IP address or domain to scan for open ports (e.g., '192.168.1.1', 'google.com').")
    ports: Optional[str] = Field(default="1-1024", description="Port range to scan (e.g., '1-1024').")

class CSPValidatorInput(BaseModel):
    url: str = Field(..., description="The URL to validate Content Security Policy headers for.")

class SecurityHeadersCheckInput(BaseModel):
    url: str = Field(..., description="The URL to check for security-related headers.")

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

class Tools:
    def __init__(self):
        self.default_timeout = 5  # Default timeout for network operations in seconds

    async def ssl_certificate_details(self, domain: str, __event_emitter__: Callable[[dict], Any] = None) -> str:
        emitter = EventEmitter(__event_emitter__)
        await emitter.progress_update(f"Fetching SSL certificate details for {domain}...")

        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    issuer = dict(x[0] for x in cert['issuer'])
                    subject = dict(x[0] for x in cert['subject'])
                    valid_from = cert['notBefore']
                    valid_to = cert['notAfter']
                    cert_details = {
                        "issuer": issuer,
                        "subject": subject,
                        "valid_from": valid_from,
                        "valid_to": valid_to,
                    }
                    await emitter.success_update(f"SSL certificate details for {domain} fetched successfully!")
                    return json.dumps(cert_details)
        except Exception as e:
            await emitter.error_update(f"SSL certificate details fetch error: {str(e)}")
            return json.dumps({"error": str(e)})

    async def open_port_scanner(self, host: str, ports: str, __event_emitter__: Callable[[dict], Any] = None) -> str:
        emitter = EventEmitter(__event_emitter__)
        await emitter.progress_update(f"Scanning open ports on {host}...")

        try:
            import nmap3
            nmap = nmap3.Nmap()
            port_range = ports
            scan_result = nmap.scan_top_ports(host, args=f"-p {port_range}")
            await emitter.success_update(f"Open port scan for {host} completed successfully!")
            return json.dumps(scan_result)
        except Exception as e:
            await emitter.error_update(f"Open port scan error: {str(e)}")
            return json.dumps({"error": str(e)})

    async def csp_validator(self, url: str, __event_emitter__: Callable[[dict], Any] = None) -> str:
        emitter = EventEmitter(__event_emitter__)
        await emitter.progress_update(f"Validating Content Security Policy (CSP) headers for {url}...")

        try:
            response = requests.get(url, timeout=self.default_timeout)
            csp_header = response.headers.get('Content-Security-Policy', 'Not Found')
            if csp_header == 'Not Found':
                await emitter.error_update(f"No CSP headers found for {url}.")
                return json.dumps({"url": url, "csp_header": "Not Found"})
            else:
                await emitter.success_update(f"CSP headers for {url} validated successfully!")
                return json.dumps({"url": url, "csp_header": csp_header})
        except requests.RequestException as e:
            await emitter.error_update(f"CSP validation error: {str(e)}")
            return json.dumps({"error": str(e)})

    async def security_headers_check(self, url: str, __event_emitter__: Callable[[dict], Any] = None) -> str:
        emitter = EventEmitter(__event_emitter__)
        await emitter.progress_update(f"Checking security-related headers for {url}...")

        try:
            response = requests.get(url, timeout=self.default_timeout)
            security_headers = {
                "X-Content-Type-Options": response.headers.get("X-Content-Type-Options", "Not Set"),
                "X-Frame-Options": response.headers.get("X-Frame-Options", "Not Set"),
                "Strict-Transport-Security": response.headers.get("Strict-Transport-Security", "Not Set"),
                "Content-Security-Policy": response.headers.get("Content-Security-Policy", "Not Set"),
                "X-XSS-Protection": response.headers.get("X-XSS-Protection", "Not Set"),
            }
            await emitter.success_update(f"Security headers check for {url} completed successfully!")
            return json.dumps(security_headers)
        except requests.RequestException as e:
            await emitter.error_update(f"Security headers check error: {str(e)}")
            return json.dumps({"error": str(e)})

# Function valves for OpenWebUI
async def ssl_certificate_details_valve(args: SSLCertificateDetailsInput, __event_emitter__: Callable[[dict], Any] = None) -> str:
    tools = Tools()
    return await tools.ssl_certificate_details(args.domain, __event_emitter__)

async def open_port_scanner_valve(args: OpenPortScannerInput, __event_emitter__: Callable[[dict], Any] = None) -> str:
    tools = Tools()
    return await tools.open_port_scanner(args.host, args.ports, __event_emitter__)

async def csp_validator_valve(args: CSPValidatorInput, __event_emitter__: Callable[[dict], Any] = None) -> str:
    tools = Tools()
    return await tools.csp_validator(args.url, __event_emitter__)

async def security_headers_check_valve(args: SecurityHeadersCheckInput, __event_emitter__: Callable[[dict], Any] = None) -> str:
    tools = Tools()
    return await tools.security_headers_check(args.url, __event_emitter__)

# Register pipelines for OpenWebUI
def register_pipelines():
    pipelines = {
        "ssl_certificate_details_pipeline": {
            "valves": [ssl_certificate_details_valve],
            "filters": [],
            "pipes": [],
        },
        "open_port_scanner_pipeline": {
            "valves": [open_port_scanner_valve],
            "filters": [],
            "pipes": [],
        },
        "csp_validator_pipeline": {
            "valves": [csp_validator_valve],
            "filters": [],
            "pipes": [],
        },
        "security_headers_check_pipeline": {
            "valves": [security_headers_check_valve],
            "filters": [],
            "pipes": [],
        },
    }
    return pipelines

pipelines = register_pipelines()
