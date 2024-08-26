"""
title: Network Toolkit
description: Comprehensive pipeline for network and security diagnostics including SSL checks, port scans, subdomain enumeration, CSP reports, HTTP checks, API validation, TCP scanning, and load time measurement.
author: pd@suicidebutton.com
date: 2024-08-24
version: 1.1
requirements: pydantic, requests, aiohttp, sublist3r, python-libnmap, ping3, scapy
"""

from typing import List, Dict, Any, Optional, Union
from pydantic import BaseModel, Field
import ssl
import socket
import requests
import logging
from libnmap.process import NmapProcess
import sublist3r
from ping3 import ping
from scapy.all import traceroute
import asyncio

logging.basicConfig(level=logging.INFO)

# Define input models
class SSLCheckInput(BaseModel):
    domain: str = Field(..., description="The domain to check SSL certificate for.")

class PortVulnerabilityScanInput(BaseModel):
    host: str = Field(..., description="The host to scan for open ports.")
    ports: Optional[List[int]] = Field(None, description="List of ports to scan (e.g., [80, 443]).")

class SubdomainEnumerationInput(BaseModel):
    domain: str = Field(..., description="The domain to enumerate subdomains for.")

class CSPReportInput(BaseModel):
    domain: str = Field(..., description="The domain to check Content Security Policy (CSP) for.")

class PingTestInput(BaseModel):
    target: str = Field(..., description="The target IP or domain to ping.")
    count: int = Field(default=4, description="Number of pings to send.")

class TraceRouteInput(BaseModel):
    target: str = Field(..., description="The target IP or domain for traceroute.")

class HTTPEndpointCheckInput(BaseModel):
    url: str = Field(..., description="The HTTP/HTTPS endpoint to check.")

class Pipeline:
    class Valves(BaseModel):
        ssl_check: bool = True
        port_vulnerability_scan: bool = True
        subdomain_enumeration: bool = True
        csp_report: bool = True
        ping_test: bool = True
        traceroute: bool = True
        http_endpoint_check: bool = True

    def __init__(self):
        self.type = "pipe"
        self.id = "network_toolkit"
        self.name = "Network Toolkit"
        self.valves = self.Valves()
        self.available_tools = {
            "ssl_check": self.ssl_check,
            "port_vulnerability_scan": self.port_vulnerability_scan,
            "subdomain_enumeration": self.subdomain_enumeration,
            "csp_report": self.csp_report,
            "ping_test": self.ping_test,
            "traceroute": self.traceroute,
            "http_endpoint_check": self.http_endpoint_check
        }

    async def on_startup(self):
        logging.info("Network Toolkit started.")

    async def on_shutdown(self):
        logging.info("Network Toolkit shutting down.")

    async def on_valves_updated(self):
        logging.info("Valves updated in Network Toolkit.")

    async def ssl_check(self, args: SSLCheckInput) -> Dict[str, Any]:
        logging.info(f"Checking SSL certificate for {args.domain}...")
        try:
            context = ssl.create_default_context()
            with socket.create_connection((args.domain, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=args.domain) as ssock:
                    cert = ssock.getpeercert()
                    ssl_info = {
                        "subject": dict(x[0] for x in cert["subject"]),
                        "issuer": dict(x[0] for x in cert["issuer"]),
                        "notBefore": cert["notBefore"],
                        "notAfter": cert["notAfter"]
                    }
                    return ssl_info
        except Exception as e:
            logging.error(f"SSL check error for {args.domain}: {str(e)}")
            return {"error": str(e)}

    async def port_vulnerability_scan(self, args: PortVulnerabilityScanInput) -> Dict[str, Any]:
        logging.info(f"Scanning vulnerabilities on {args.host}...")
        try:
            ports = ','.join(map(str, args.ports)) if args.ports else '1-65535'
            nmap_proc = NmapProcess(targets=args.host, options=f'-sV --script vuln -p {ports}')
            nmap_proc.run()
            
            if nmap_proc.rc == 0:
                return {"output": nmap_proc.stdout}
            else:
                logging.error(f"Error scanning ports: {nmap_proc.stderr}")
                return {"error": nmap_proc.stderr}
        except Exception as e:
            logging.error(f"Port scan error on {args.host}: {str(e)}")
            return {"error": str(e)}

    async def subdomain_enumeration(self, args: SubdomainEnumerationInput) -> List[str]:
        logging.info(f"Enumerating subdomains for {args.domain}...")
        try:
            subdomains = sublist3r.main(args.domain, 40, silent=True, verbose=False)
            return subdomains
        except Exception as e:
            logging.error(f"Subdomain enumeration error for {args.domain}: {str(e)}")
            return [f"Error: {str(e)}"]

    async def csp_report(self, args: CSPReportInput) -> str:
        logging.info(f"Checking CSP for {args.domain}...")
        try:
            response = requests.get(f"https://{args.domain}", verify=False)
            csp = response.headers.get("Content-Security-Policy", "No CSP header found.")
            return csp
        except requests.RequestException as e:
            logging.error(f"CSP check error for {args.domain}: {str(e)}")
            return f"Error: {str(e)}"

    async def ping_test(self, args: PingTestInput) -> Dict[str, Any]:
        logging.info(f"Pinging {args.target}...")
        results = []
        for _ in range(args.count):
            delay = ping(args.target, timeout=1)
            results.append(f"Ping to {args.target} {'successful' if delay is not None else 'failed'}, delay: {delay if delay is not None else 'N/A'} ms")
        return {"results": results}

    async def traceroute(self, args: TraceRouteInput) -> Dict[str, Any]:
        logging.info(f"Running traceroute to {args.target}...")
        try:
            res, _ = traceroute(args.target, verbose=0)
            routes = {str(route[1].src): str(route[1].time) for route in res}
            return routes
        except Exception as e:
            logging.error(f"Traceroute error to {args.target}: {str(e)}")
            return {"error": str(e)}

    async def http_endpoint_check(self, args: HTTPEndpointCheckInput) -> Dict[str, Any]:
        logging.info(f"Checking HTTP/HTTPS endpoint: {args.url}...")
        try:
            response = requests.get(args.url, timeout=10)
            response.raise_for_status()
            return {
                "status_code": response.status_code,
                "headers": dict(response.headers),
                "content_length": len(response.content)
            }
        except requests.RequestException as e:
            logging.error(f"Endpoint check error for {args.url}: {str(e)}")
            return {"error": str(e)}

    async def execute_tool(self, tool_id: str, args: Dict[str, Any]) -> Union[str, Dict[str, Any]]:
        if tool_id in self.available_tools and self.valves.dict().get(tool_id, False):
            return await self.available_tools[tool_id](args)
        else:
            return {"error": f"Tool {tool_id} not found or is disabled."}

    async def pipe(self, user_message: str, model_id: str, messages: List[dict], body: dict) -> Dict[str, Any]:
        tool_id = body.get('tool_id')
        args = body.get('input')

        if tool_id and args:
            try:
                result = await self.execute_tool(tool_id, args)
                return {"status": "success", "details": result}
            except Exception as err:
                logging.error(f"Error during tool execution: {str(err)}")
                return {"status": "error", "message": str(err)}
        else:
            return {"status": "error", "message": "Invalid tool ID or missing arguments."}

# Register the pipeline
def register_pipelines():
    return {
        "network_toolkit": {
            "run": Pipeline().pipe,
            "valves": True,
            "default_valve": "pipe"
        }
    }

