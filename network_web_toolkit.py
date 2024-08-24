"""
title: Web Diagnostic Toolkit
author: Phil Dougherty
email: pd@suicidebutton.com
date: 2024-08-24
version: 1.0
license: MIT
description: General tools for web/endpoint diagnostics and testing.
"""

import json
import logging
import requests
from urllib.parse import urlparse
from datetime import datetime
from pydantic import BaseModel, Field
from typing import Optional, Callable, Any

logging.basicConfig(level=logging.INFO)

# Input models
class HTTPRequestInput(BaseModel):
    url: str = Field(..., description="The URL to send an HTTP request to.")
    method: str = Field(default="GET", description="The HTTP method to use (e.g., 'GET', 'POST').")
    headers: Optional[dict] = Field(default=None, description="Optional HTTP headers to include in the request.")
    data: Optional[dict] = Field(default=None, description="Optional data to send with the request for POST/PUT methods.")

class SSLCheckInput(BaseModel):
    url: str = Field(..., description="The URL to check SSL certificate details.")

class DNSLookupInput(BaseModel):
    domain: str = Field(..., description="The domain name to look up DNS records for (e.g., 'google.com').")

class ContentSecurityPolicyInput(BaseModel):
    url: str = Field(..., description="The URL to check Content Security Policy (CSP) headers.")

class SubdomainEnumerationInput(BaseModel):
    domain: str = Field(..., description="The domain to enumerate subdomains for (e.g., 'google.com').")

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
        self.default_timeout = 5  # Default timeout for web operations in seconds

    async def http_request(self, url: str, method: str, headers: dict = None, data: dict = None, __event_emitter__: Callable[[dict], Any] = None) -> str:
        emitter = EventEmitter(__event_emitter__)
        await emitter.progress_update(f"Sending {method} request to {url}...")

        try:
            response = requests.request(method, url, headers=headers, data=data, timeout=self.default_timeout)
            response.raise_for_status()
            await emitter.success_update(f"HTTP request to {url} completed successfully!")
            return json.dumps({"url": url, "status_code": response.status_code, "headers": dict(response.headers), "body": response.text})
        except requests.RequestException as e:
            await emitter.error_update(f"HTTP request error: {str(e)}")
            return json.dumps({"error": str(e)})

    async def ssl_check(self, url: str, __event_emitter__: Callable[[dict], Any] = None) -> str:
        emitter = EventEmitter(__event_emitter__)
        await emitter.progress_update(f"Checking SSL certificate for {url}...")

        try:
            parsed_url = urlparse(url)
            hostname = parsed_url.hostname

            response = requests.get(f"https://{hostname}", timeout=self.default_timeout)
            cert = response.raw.connection.sock.getpeercert()
            await emitter.success_update(f"SSL certificate check for {url} completed successfully!")
            return json.dumps({"subject": dict(x[0] for x in cert['subject']), "issuer": dict(x[0] for x in cert['issuer']), "valid_from": cert['notBefore'], "valid_to": cert['notAfter']})
        except Exception as e:
            await emitter.error_update(f"SSL check error: {str(e)}")
            return json.dumps({"error": str(e)})

    async def dns_lookup(self, domain: str, __event_emitter__: Callable[[dict], Any] = None) -> str:
        emitter = EventEmitter(__event_emitter__)
        await emitter.progress_update(f"Looking up DNS records for {domain}...")

        try:
            import dns.resolver
            result = {}
            for record_type in ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME']:
                answers = dns.resolver.resolve(domain, record_type, raise_on_no_answer=False)
                result[record_type] = [answer.to_text() for answer in answers]
            await emitter.success_update(f"DNS lookup for {domain} completed successfully!")
            return json.dumps(result)
        except dns.resolver.NoAnswer:
            await emitter.error_update(f"No DNS records found for {domain}.")
            return json.dumps({"error": f"No DNS records found for {domain}."})
        except Exception as e:
            await emitter.error_update(f"DNS lookup error: {str(e)}")
            return json.dumps({"error": str(e)})

    async def content_security_policy_check(self, url: str, __event_emitter__: Callable[[dict], Any] = None) -> str:
        emitter = EventEmitter(__event_emitter__)
        await emitter.progress_update(f"Checking Content Security Policy (CSP) headers for {url}...")

        try:
            response = requests.get(url, timeout=self.default_timeout)
            csp_header = response.headers.get('Content-Security-Policy', 'Not Found')
            await emitter.success_update(f"CSP header check for {url} completed successfully!")
            return json.dumps({"url": url, "csp_header": csp_header})
        except requests.RequestException as e:
            await emitter.error_update(f"CSP check error: {str(e)}")
            return json.dumps({"error": str(e)})

    async def subdomain_enumeration(self, domain: str, __event_emitter__: Callable[[dict], Any] = None) -> str:
        emitter = EventEmitter(__event_emitter__)
        await emitter.progress_update(f"Enumerating subdomains for {domain}...")

        try:
            import sublist3r
            subdomains = sublist3r.main(domain, 40, None, ports=None, silent=True, verbose=False, enable_bruteforce=False, engines=None)
            await emitter.success_update(f"Subdomain enumeration for {domain} completed successfully!")
            return json.dumps({"domain": domain, "subdomains": subdomains})
        except Exception as e:
            await emitter.error_update(f"Subdomain enumeration error: {str(e)}")
            return json.dumps({"error": str(e)})

# Function valves for OpenWebUI
async def http_request_valve(args: HTTPRequestInput, __event_emitter__: Callable[[dict], Any] = None) -> str:
    tools = Tools()
    return await tools.http_request(args.url, args.method, args.headers, args.data, __event_emitter__)

async def ssl_check_valve(args: SSLCheckInput, __event_emitter__: Callable[[dict], Any] = None) -> str:
    tools = Tools()
    return await tools.ssl_check(args.url, __event_emitter__)

async def dns_lookup_valve(args: DNSLookupInput, __event_emitter__: Callable[[dict], Any] = None) -> str:
    tools = Tools()
    return await tools.dns_lookup(args.domain, __event_emitter__)

async def content_security_policy_valve(args: ContentSecurityPolicyInput, __event_emitter__: Callable[[dict], Any] = None) -> str:
    tools = Tools()
    return await tools.content_security_policy_check(args.url, __event_emitter__)

async def subdomain_enumeration_valve(args: SubdomainEnumerationInput, __event_emitter__: Callable[[dict], Any] = None) -> str:
    tools = Tools()
    return await tools.subdomain_enumeration(args.domain, __event_emitter__)

# Register pipelines for OpenWebUI
def register_pipelines():
    pipelines = {
        "http_request_pipeline": {
            "valves": [http_request_valve],
            "filters": [],
            "pipes": [],
        },
        "ssl_check_pipeline": {
            "valves": [ssl_check_valve],
            "filters": [],
            "pipes": [],
        },
        "dns_lookup_pipeline": {
            "valves": [dns_lookup_valve],
            "filters": [],
            "pipes": [],
        },
        "content_security_policy_pipeline": {
            "valves": [content_security_policy_valve],
            "filters": [],
            "pipes": [],
        },
        "subdomain_enumeration_pipeline": {
            "valves": [subdomain_enumeration_valve],
            "filters": [],
            "pipes": [],
        },
    }
    return pipelines

pipelines = register_pipelines()
