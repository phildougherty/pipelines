"""
title: Network Diagnostics Toolkit
description: Comprehensive pipeline for network and security diagnostics including SSL checks, port scans, subdomain enumeration, CSP reports, HTTP checks, API validation, TCP scanning, and load time measurement.
author: pd@suicidebutton.com
date: 2024-08-28
version: 1.0
license: MIT
requirements: pydantic, requests, aiohttp
"""

from open_webui import Pipeline, PipelineApp, component
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

# Input Models for the Valves
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

# Combined Toolkit Class with ASGI-compatible Components
class CombinedNetworkSecurityToolkit:
    @component
    async def ssl_check(self, args: SSLCheckInput, event_emitter: Callable[[dict], Any] = None) -> str:
        """
        Check SSL certificate details for a given domain.
        """
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

    @component
    async def port_vulnerability_scan(self, args: PortVulnerabilityScanInput, event_emitter: Callable[[dict], Any] = None) -> str:
        """
        Perform a port vulnerability scan on a given host.
        """
        emitter = EventEmitter(event_emitter)
        await emitter.emit(f"Scanning ports for vulnerabilities on {args.host}...")

        try:
            nmap_args = ["nmap", "-sV", "--script", "vuln", args.host]
            if args.ports:
                nmap_args.extend(["-p", args.ports])

            result = subprocess.check_output(nmap_args, stderr=subprocess.STDOUT).decode('utf-8')
            await emitter.emit(f"Port vulnerability scan on {args.host} complete!", "success", True)
            return result
        except subprocess.CalledProcessError as e:
            await emitter.emit(f"Error during port vulnerability scan: {e.output.decode('utf-8')}", "error", True)
            return json.dumps({"error": e.output.decode('utf-8')})

    @component
    async def subdomain_enumeration(self, args: SubdomainEnumerationInput, event_emitter: Callable[[dict], Any] = None) -> str:
        """
        Enumerate subdomains for a given domain.
        """
        emitter = EventEmitter(event_emitter)
        await emitter.emit(f"Enumerating subdomains for {args.domain}...")

        try:
            subdomains = []
            # Use Sublist3r or a similar library to enumerate subdomains
            import sublist3r
            subdomains = sublist3r.main(args.domain, 40, ports=None, silent=True, verbose=False, enable_bruteforce=False, engines=None)
            await emitter.emit(f"Subdomain enumeration for {args.domain} complete!", "success", True)
            return json.dumps({"subdomains": subdomains})
        except Exception as e:
            await emitter.emit(f"Error during subdomain enumeration: {str(e)}", "error", True)
            return json.dumps({"error": str(e)})

    @component
    async def csp_report(self, args: CSPReportInput, event_emitter: Callable[[dict], Any] = None) -> str:
        """
        Generate a Content Security Policy (CSP) report for a given domain.
        """
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

    @component
    async def ping_test(self, args: PingTestInput, event_emitter: Callable[[dict], Any] = None) -> str:
        """
        Run a ping test to a given target.
        """
        emitter = EventEmitter(event_emitter)
        await emitter.emit(f"Running ping test to {args.target}...")

        try:
            command = ['ping', '-c', str(args.count), args.target]
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

    @component
    async def mtu_discovery(self, args: MTUDiscoveryInput, event_emitter: Callable[[dict], Any] = None) -> str:
        """
        Discover MTU for a given target.
        """
        emitter = EventEmitter(event_emitter)
        await emitter.emit(f"Discovering MTU for {args.target}...")

        try:
            mtu = 1500  # Starting MTU value
            command = ['ping', '-c', '1', '-M', 'do', '-s', str(mtu), args.target]
            while mtu > 0:
                result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                if 'Frag needed' in result.stderr:
                    mtu -= 10  # Decrease packet size
                else:
                    break
                command = ['ping', '-c', '1', '-M', 'do', '-s', str(mtu), args.target]
            await emitter.emit(f"MTU discovery for {args.target} complete. MTU: {mtu}", "success", True)
            return f"MTU for {args.target} is {mtu}"
        except Exception as e:
            await emitter.emit(f"MTU discovery error: {str(e)}", "error", True)
            return str(e)

    @component
    async def traceroute(self, args: TraceRouteInput, event_emitter: Callable[[dict], Any] = None) -> str:
        """
        Perform a traceroute to a given target.
        """
        emitter = EventEmitter(event_emitter)
        await emitter.emit(f"Running traceroute to {args.target}...")

        try:
            command = ['traceroute', args.target]
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

    @component
    async def multi_protocol_test(self, args: MultiProtocolTestInput, event_emitter: Callable[[dict], Any] = None) -> str:
        """
        Run multiple network diagnostics for a given target.
        """
        emitter = EventEmitter(event_emitter)
        await emitter.emit(f"Running multi-protocol test for {args.target}...")

        results = []
        try:
            # Running ping test
            ping_result = await self.ping_test(PingTestInput(target=args.target), event_emitter)
            results.append(f"Ping Test:\n{ping_result}")

            # Running traceroute test
            traceroute_result = await self.traceroute(TraceRouteInput(target=args.target), event_emitter)
            results.append(f"Traceroute:\n{traceroute_result}")

            # Running MTU discovery test
            mtu_result = await self.mtu_discovery(MTUDiscoveryInput(target=args.target), event_emitter)
            results.append(f"MTU Discovery:\n{mtu_result}")

            await emitter.emit(f"Multi-protocol test for {args.target} complete.", "success", True)
            return "\n\n".join(results)
        except Exception as e:
            await emitter.emit(f"Multi-protocol test error: {str(e)}", "error", True)
            return str(e)

    @component
    async def http_endpoint_check(self, args: HTTPEndpointCheckInput, event_emitter: Callable[[dict], Any] = None) -> str:
        """
        Check HTTP/HTTPS endpoint status.
        """
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

    @component
    async def api_response_validator(self, args: APIResponseValidatorInput, event_emitter: Callable[[dict], Any] = None) -> str:
        """
        Validate API response structure.
        """
        emitter = EventEmitter(event_emitter)
        await emitter.emit(f"Validating API response from {args.url}...")

        try:
            response = requests.get(args.url, timeout=10)
            response.raise_for_status()
            response_json = response.json()

            # Validate response structure
            if self.validate_structure(response_json, args.expected_structure):
                await emitter.emit(f"API response from {args.url} matches expected structure.", "success", True)
                return "Valid API response structure"
            else:
                await emitter.emit(f"API response from {args.url} does not match expected structure.", "error", True)
                return "Invalid API response structure"
        except requests.RequestException as e:
            await emitter.emit(f"Error validating API response from {args.url}: {str(e)}", "error", True)
            return str(e)

    def validate_structure(self, response: dict, expected_structure: dict) -> bool:
        """
        Validate that the response structure matches the expected structure.
        """
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

    @component
    async def tcp_service_scan(self, args: TCPServiceScannerInput, event_emitter: Callable[[dict], Any] = None) -> str:
        """
        Perform a TCP service scan on a target host.
        """
        emitter = EventEmitter(event_emitter)
        await emitter.emit(f"Scanning TCP services on host {args.host} in range {args.port_range}...")

        open_ports = []
        try:
            start_port, end_port = map(int, args.port_range.split('-'))
            for port in range(start_port, end_port + 1):
                result = self.check_port(args.host, port)
                if result:
                    open_ports.append(port)

            await emitter.emit(f"TCP service scan on {args.host} complete.", "success", True)
            return f"Open ports: {open_ports}"
        except Exception as e:
            await emitter.emit(f"Error during TCP service scan on {args.host}: {str(e)}", "error", True)
            return str(e)

    def check_port(self, host: str, port: int) -> bool:
        """
        Check if a specific TCP port is open on a host.
        """
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(10)
            result = sock.connect_ex((host, port))
            return result == 0

    @component
    async def load_time_measurement(self, args: LoadTimeMeasurementInput, event_emitter: Callable[[dict], Any] = None) -> str:
        """
        Measure the load time of a web page.
        """
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

# Define and Register the Pipeline
def register_pipelines():
    toolkit = CombinedNetworkSecurityToolkit()
    pipeline = Pipeline(
        name="combined_network_security_pipeline",
        description="Comprehensive pipeline for network and security diagnostics including SSL checks, port scans, subdomain enumeration, CSP reports, HTTP checks, API validation, TCP scanning, and load time measurement."
    )

    # Add all components to the pipeline
    pipeline.add_component(toolkit.ssl_check, input_model=SSLCheckInput)
    pipeline.add_component(toolkit.port_vulnerability_scan, input_model=PortVulnerabilityScanInput)
    pipeline.add_component(toolkit.subdomain_enumeration, input_model=SubdomainEnumerationInput)
    pipeline.add_component(toolkit.csp_report, input_model=CSPReportInput)
    pipeline.add_component(toolkit.ping_test, input_model=PingTestInput)
    pipeline.add_component(toolkit.mtu_discovery, input_model=MTUDiscoveryInput)
    pipeline.add_component(toolkit.traceroute, input_model=TraceRouteInput)
    pipeline.add_component(toolkit.multi_protocol_test, input_model=MultiProtocolTestInput)
    pipeline.add_component(toolkit.http_endpoint_check, input_model=HTTPEndpointCheckInput)
    pipeline.add_component(toolkit.api_response_validator, input_model=APIResponseValidatorInput)
    pipeline.add_component(toolkit.tcp_service_scan, input_model=TCPServiceScannerInput)
    pipeline.add_component(toolkit.load_time_measurement, input_model=LoadTimeMeasurementInput)

    return {"combined_network_security_pipeline": pipeline}

# Initialize and Run the Application
app = PipelineApp(register_pipelines=register_pipelines)

if __name__ == "__main__":
    app.run()

# Ensure the `app` is exposed for ASGI
if __name__ != "__main__":
    from network_toolkit import app
