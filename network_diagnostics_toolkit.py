"""
title: Network Diagnostics Toolkit
description: Comprehensive toolkit for network and security diagnostics including SSL checks, port scans, subdomain enumeration, CSP reports, HTTP checks, API validation, TCP scanning, and load time measurement.
author: pd@suicidebutton.com
date: 2024-08-24
version: 1.0
requirements: pydantic,requests,aiohttp,sublist3r,uvicorn,fastapi
"""

from pydantic import BaseModel, Field
from typing import Callable, Any, Optional
import ssl
import socket
import requests
import json
import subprocess
import asyncio
import aiohttp
import logging
import time
from fastapi import FastAPI, BackgroundTasks
from fastapi.responses import JSONResponse

# Input Models for the Components
class SSLCheckInput(BaseModel):
    domain: str = Field(..., description="The domain name to check SSL certificate for.")

class PortVulnerabilityScanInput(BaseModel):
    host: str = Field(..., description="The host to scan for open ports.")
    ports: Optional[str] = Field(None, description="Comma-separated list of ports to scan (e.g., '80,443').")

class SubdomainEnumerationInput(BaseModel):
    domain: str = Field(..., description="The domain name to enumerate subdomains for.")

class CSPReportInput(BaseModel):
    domain: str = Field(..., description="The domain name to check Content Security Policy (CSP) for.")

class PingTestInput(BaseModel):
    target: str = Field(..., description="The target IP or domain to ping (e.g., '8.8.8.8', 'google.com').")
    count: int = Field(default=4, description="Number of ping requests to send.")

class MTUDiscoveryInput(BaseModel):
    target: str = Field(..., description="The target IP or domain to discover MTU (e.g., '8.8.8.8', 'google.com').")

class TraceRouteInput(BaseModel):
    target: str = Field(..., description="The target IP or domain for traceroute (e.g., '8.8.8.8', 'google.com').")

class MultiProtocolTestInput(BaseModel):
    target: str = Field(..., description="The target IP or domain to test (e.g., '8.8.8.8', 'google.com').")

class HTTPEndpointCheckInput(BaseModel):
    url: str = Field(..., description="The URL of the HTTP/HTTPS endpoint to check (e.g., 'https://google.com').")

class APIResponseValidatorInput(BaseModel):
    url: str = Field(..., description="The URL of the API endpoint to validate.")
    expected_structure: dict = Field(..., description="The expected structure of the API response in a dictionary format.")

class TCPServiceScannerInput(BaseModel):
    host: str = Field(..., description="The target host to scan (e.g., '192.168.1.1').")
    port_range: str = Field(..., description="The range of ports to scan (e.g., '20-80').")

class LoadTimeMeasurementInput(BaseModel):
    url: str = Field(..., description="The URL of the web page to measure load time (e.g., 'https://example.com').")

# Logging setup
logging.basicConfig(level=logging.INFO)

# Event emitter class for handling progress updates
class EventEmitter:
    def __init__(self, event_emitter: Callable[[dict], Any] = None):
        self.event_emitter = event_emitter

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

# Component Functions
async def ssl_check(args: SSLCheckInput, event_emitter: Callable[[dict], Any] = None) -> str:
    emitter = EventEmitter(event_emitter)
    await emitter.emit(f"Checking SSL certificate for {args.domain}...")
    try:
        context = ssl.create_default_context()
        with socket.create_connection((args.domain, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=args.domain) as ssock:
                cert = ssock.getpeercert()
                ssl_info = {
                    "subject": dict(x[0] for x in cert["subject"]),
                    "issuer": dict(x[0] for x in cert["issuer"]),
                    "notBefore": cert["notBefore"],
                    "notAfter": cert["notAfter"],
                }
                await emitter.emit(f"SSL check for {args.domain} complete!", "success", True)
                return json.dumps(ssl_info)
    except Exception as e:
        await emitter.emit(f"SSL check error for {args.domain}: {str(e)}", "error", True)
        return json.dumps({"error": str(e)})

async def port_vulnerability_scan(args: PortVulnerabilityScanInput, event_emitter: Callable[[dict], Any] = None) -> str:
    emitter = EventEmitter(event_emitter)
    await emitter.emit(f"Scanning ports for vulnerabilities on {args.host}...")
    try:
        nmap_args = ["nmap", "-sV", "--script", "vuln", args.host]
        if args.ports:
            nmap_args.extend(["-p", args.ports])
        result = subprocess.check_output(nmap_args, stderr=subprocess.STDOUT).decode("utf-8")
        await emitter.emit(f"Port vulnerability scan on {args.host} complete!", "success", True)
        return result
    except subprocess.CalledProcessError as e:
        await emitter.emit(f"Error during port vulnerability scan: {e.output.decode('utf-8')}", "error", True)
        return json.dumps({"error": e.output.decode("utf-8")})

async def subdomain_enumeration(args: SubdomainEnumerationInput, event_emitter: Callable[[dict], Any] = None) -> str:
    emitter = EventEmitter(event_emitter)
    await emitter.emit(f"Enumerating subdomains for {args.domain}...")
    try:
        subdomains = []
        import sublist3r
        subdomains = sublist3r.main(args.domain, 40, ports=None, silent=True, verbose=False, enable_bruteforce=False, engines=None)
        await emitter.emit(f"Subdomain enumeration for {args.domain} complete!", "success", True)
        return json.dumps({"subdomains": subdomains})
    except Exception as e:
        await emitter.emit(f"Error during subdomain enumeration: {str(e)}", "error", True)
        return json.dumps({"error": str(e)})

async def csp_report(args: CSPReportInput, event_emitter: Callable[[dict], Any] = None) -> str:
    emitter = EventEmitter(event_emitter)
    await emitter.emit(f"Checking Content Security Policy (CSP) for {args.domain}...")
    try:
        response = requests.get(f"https://{args.domain}", verify=False)
        csp = response.headers.get("Content-Security-Policy", "No CSP header found.")
        await emitter.emit(f"CSP check for {args.domain} complete!", "success", True)
        return json.dumps({"CSP": csp})
    except requests.RequestException as e:
        await emitter.emit(f"Error during CSP check: {str(e)}", "error", True)
        return json.dumps({"error": str(e)})

async def ping_test(args: PingTestInput, event_emitter: Callable[[dict], Any] = None) -> str:
    emitter = EventEmitter(event_emitter)
    await emitter.emit(f"Running ping test to {args.target}...")
    try:
        command = ["ping", "-c", str(args.count), args.target]
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if result.returncode == 0:
            await emitter.emit(f"Ping test to {args.target} succeeded.", "success", True)
            return result.stdout
        else:
            await emitter.emit(f"Ping test to {args.target} failed.", "error", True)
            return result.stderr
    except Exception as e:
        await emitter.emit(f"Ping test error: {str(e)}", "error", True)
        return str(e)

async def mtu_discovery(args: MTUDiscoveryInput, event_emitter: Callable[[dict], Any] = None) -> str:
    emitter = EventEmitter(event_emitter)
    await emitter.emit(f"Discovering MTU for {args.target}...")
    try:
        mtu = 1500  # Starting MTU value
        command = ["ping", "-c", "1", "-M", "do", "-s", str(mtu), args.target]
        while mtu > 0:
            result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            if "Frag needed" in result.stderr or "Message too long" in result.stderr:
                mtu -= 10  # Decrease packet size
                command = ["ping", "-c", "1", "-M", "do", "-s", str(mtu), args.target]
            else:
                break
        await emitter.emit(f"MTU discovery for {args.target} complete. MTU: {mtu}", "success", True)
        return f"MTU for {args.target} is {mtu}"
    except Exception as e:
        await emitter.emit(f"MTU discovery error: {str(e)}", "error", True)
        return json.dumps({"error": str(e)})

async def traceroute(args: TraceRouteInput, event_emitter: Callable[[dict], Any] = None) -> str:
    emitter = EventEmitter(event_emitter)
    await emitter.emit(f"Running traceroute to {args.target}...")
    try:
        command = ["traceroute", args.target]
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if result.returncode == 0:
            await emitter.emit(f"Traceroute to {args.target} completed.", "success", True)
            return result.stdout
        else:
            await emitter.emit(f"Traceroute to {args.target} failed.", "error", True)
            return result.stderr
    except Exception as e:
        await emitter.emit(f"Traceroute error: {str(e)}", "error", True)
        return str(e)

async def multi_protocol_test(args: MultiProtocolTestInput, event_emitter: Callable[[dict], Any] = None) -> str:
    emitter = EventEmitter(event_emitter)
    await emitter.emit(f"Running multi-protocol test for {args.target}...")
    results = []
    try:
        ping_result = await ping_test(PingTestInput(target=args.target), event_emitter)
        results.append(f"Ping Test:\n{ping_result}")

        traceroute_result = await traceroute(TraceRouteInput(target=args.target), event_emitter)
        results.append(f"Traceroute:\n{traceroute_result}")

        mtu_result = await mtu_discovery(MTUDiscoveryInput(target=args.target), event_emitter)
        results.append(f"MTU Discovery:\n{mtu_result}")

        await emitter.emit(f"Multi-protocol test for {args.target} complete.", "success", True)
        return "\n\n".join(results)
    except Exception as e:
        await emitter.emit(f"Multi-protocol test error: {str(e)}", "error", True)
        return str(e)

async def http_endpoint_check(args: HTTPEndpointCheckInput, event_emitter: Callable[[dict], Any] = None) -> str:
    emitter = EventEmitter(event_emitter)
    await emitter.emit(f"Checking HTTP/HTTPS endpoint: {args.url}...")
    try:
        response = requests.get(args.url, timeout=10)
        response.raise_for_status()
        await emitter.emit(f"Endpoint check for {args.url} succeeded with status code {response.status_code}.", "success", True)
        return response.text
    except requests.RequestException as e:
        await emitter.emit(f"Endpoint check for {args.url} failed: {str(e)}", "error", True)
        return str(e)

async def api_response_validator(args: APIResponseValidatorInput, event_emitter: Callable[[dict], Any] = None) -> str:
    emitter = EventEmitter(event_emitter)
    await emitter.emit(f"Validating API response from {args.url}...")
    try:
        response = requests.get(args.url, timeout=10)
        response.raise_for_status()
        response_json = response.json()

        if validate_structure(response_json, args.expected_structure):
            await emitter.emit(f"API response from {args.url} matches expected structure.", "success", True)
            return "Valid API response structure"
        else:
            await emitter.emit(f"API response from {args.url} does not match expected structure.", "error", True)
            return "Invalid API response structure"
    except requests.RequestException as e:
        await emitter.emit(f"Error validating API response from {args.url}: {str(e)}", "error", True)
        return str(e)

def validate_structure(response: dict, expected_structure: dict) -> bool:
    def validate(response_part, expected_part):
        if isinstance(expected_part, dict):
            if not isinstance(response_part, dict):
                return False
            for key, subpart in expected_part.items():
                if key not in response_part or not validate(response_part[key], subpart):
                    return False
        elif isinstance(expected_part, list):
            if not isinstance(response_part, list) or len(response_part) != len(expected_part):
                return False
            for subpart, expected_subpart in zip(response_part, expected_part):
                if not validate(subpart, expected_subpart):
                    return False
        return True

    return validate(response, expected_structure)

async def tcp_service_scan(args: TCPServiceScannerInput, event_emitter: Callable[[dict], Any] = None) -> str:
    emitter = EventEmitter(event_emitter)
    await emitter.emit(f"Scanning TCP services on host {args.host} in range {args.port_range}...")
    open_ports = []
    try:
        start_port, end_port = map(int, args.port_range.split("-"))
        for port in range(start_port, end_port + 1):
            result = check_port(args.host, port)
            if result:
                open_ports.append(port)
        await emitter.emit(f"TCP service scan on {args.host} complete.", "success", True)
        return f"Open ports: {open_ports}"
    except Exception as e:
        await emitter.emit(f"Error during TCP service scan on {args.host}: {str(e)}", "error", True)
        return str(e)

def check_port(host: str, port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(10)
        result = sock.connect_ex((host, port))
        return result == 0

async def load_time_measurement(args: LoadTimeMeasurementInput, event_emitter: Callable[[dict], Any] = None) -> str:
    emitter = EventEmitter(event_emitter)
    await emitter.emit(f"Measuring load time for web page {args.url}...")
    try:
        start_time = time.time()
        async with aiohttp.ClientSession() as session:
            async with session.get(args.url, timeout=10) as response:
                await response.text()  # To actually load the content
        end_time = time.time()
        load_time = end_time - start_time

        await emitter.emit(f"Load time for {args.url}: {load_time:.2f} seconds.", "success", True)
        return f"Load time: {load_time:.2f} seconds"
    except Exception as e:
        await emitter.emit(f"Error measuring load time for {args.url}: {str(e)}", "error", True)
        return str(e)

# Main function to run all components
async def run_network_diagnostics(target: str, event_emitter: Callable[[dict], Any] = None):
    results = {}
    emitter = EventEmitter(event_emitter)

    # SSL Check
    await emitter.emit("Starting SSL Check")
    ssl_result = await ssl_check(SSLCheckInput(domain=target), event_emitter)
    results["ssl_check"] = ssl_result

    # Port Vulnerability Scan
    await emitter.emit("Starting Port Vulnerability Scan")
    port_scan_result = await port_vulnerability_scan(PortVulnerabilityScanInput(host=target), event_emitter)
    results["port_vulnerability_scan"] = port_scan_result

    # Subdomain Enumeration
    await emitter.emit("Starting Subdomain Enumeration")
    subdomain_result = await subdomain_enumeration(SubdomainEnumerationInput(domain=target), event_emitter)
    results["subdomain_enumeration"] = subdomain_result

    # CSP Report
    await emitter.emit("Starting CSP Report")
    csp_result = await csp_report(CSPReportInput(domain=target), event_emitter)
    results["csp_report"] = csp_result

    # Multi-Protocol Test
    await emitter.emit("Starting Multi-Protocol Test")
    multi_protocol_result = await multi_protocol_test(MultiProtocolTestInput(target=target), event_emitter)
    results["multi_protocol_test"] = multi_protocol_result

    # HTTP Endpoint Check
    await emitter.emit("Starting HTTP Endpoint Check")
    http_result = await http_endpoint_check(HTTPEndpointCheckInput(url=f"https://{target}"), event_emitter)
    results["http_endpoint_check"] = http_result

    # TCP Service Scan
    await emitter.emit("Starting TCP Service Scan")
    tcp_scan_result = await tcp_service_scan(TCPServiceScannerInput(host=target, port_range="1-1000"), event_emitter)
    results["tcp_service_scan"] = tcp_scan_result

    # Load Time Measurement
    await emitter.emit("Starting Load Time Measurement")
    load_time_result = await load_time_measurement(LoadTimeMeasurementInput(url=f"https://{target}"), event_emitter)
    results["load_time_measurement"] = load_time_result

    await emitter.emit("Network Diagnostics Complete", "success", True)
    return results

# FastAPI app
app = FastAPI()

@app.post("/run_diagnostics")
async def run_diagnostics(target: str, background_tasks: BackgroundTasks):
    async def run_in_background():
        results = await run_network_diagnostics(target)
        # Here you would typically store or process the results
        logging.info(f"Diagnostics completed for {target}")
        logging.info(f"Results: {results}")

    background_tasks.add_task(run_in_background)
    return JSONResponse(content={"message": "Diagnostics started", "target": target})

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000
