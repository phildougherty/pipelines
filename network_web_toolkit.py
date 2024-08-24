### **2. Web/Endpoint Diagnostic Toolkit - Full Implementation**

Below is the fully implemented Web/Endpoint Diagnostic Toolkit. This toolkit focuses on diagnosing and interacting with web services and network endpoints, including HTTP/HTTPS checks, API validation, TCP scanning, and load time measurement.

#### **Python Implementation**

```python
"""
title: Web/Endpoint Diagnostic Toolkit
author: Phil Dougherty
email: pd@suicidebutton.com
date: 2024-08-28
version: 2.0
license: MIT
description: Toolkit for diagnosing and interacting with web and endpoint services.
"""

import requests
import socket
import time
from datetime import datetime
from pydantic import BaseModel, Field
from typing import Optional, Callable, Any
import asyncio
import aiohttp
import logging

logging.basicConfig(level=logging.INFO)

# Input models for the valves
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

# Core diagnostic functions
class WebEndpointToolkit:
    def __init__(self):
        self.default_timeout = 10  # Default timeout for network operations in seconds

    async def http_endpoint_check(
        self, url: str, __event_emitter__: Callable[[dict], Any] = None
    ) -> str:
        emitter = EventEmitter(__event_emitter__)
        await emitter.progress_update(f"Checking HTTP/HTTPS endpoint: {url}...")

        try:
            response = requests.get(url, timeout=self.default_timeout)
            response.raise_for_status()
            await emitter.success_update(f"Endpoint check for {url} succeeded with status code {response.status_code}.")
            return response.text
        except requests.RequestException as e:
            await emitter.error_update(f"Endpoint check for {url} failed: {str(e)}")
            return str(e)

    async def api_response_validator(
        self, url: str, expected_structure: dict, __event_emitter__: Callable[[dict], Any] = None
    ) -> str:
        emitter = EventEmitter(__event_emitter__)
        await emitter.progress_update(f"Validating API response from {url}...")

        try:
            response = requests.get(url, timeout=self.default_timeout)
            response.raise_for_status()
            response_json = response.json()

            # Validate response structure
            if self.validate_structure(response_json, expected_structure):
                await emitter.success_update(f"API response from {url} matches expected structure.")
                return "Valid API response structure"
            else:
                await emitter.error_update(f"API response from {url} does not match expected structure.")
                return "Invalid API response structure"
        except requests.RequestException as e:
            await emitter.error_update(f"Error validating API response from {url}: {str(e)}")
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

    async def tcp_service_scan(
        self, host: str, port_range: str, __event_emitter__: Callable[[dict], Any] = None
    ) -> str:
        emitter = EventEmitter(__event_emitter__)
        await emitter.progress_update(f"Scanning TCP services on host {host} in range {port_range}...")

        open_ports = []
        try:
            start_port, end_port = map(int, port_range.split('-'))
            for port in range(start_port, end_port + 1):
                result = self.check_port(host, port)
                if result:
                    open_ports.append(port)

            await emitter.success_update(f"TCP service scan on {host} complete.")
            return f"Open ports: {open_ports}"
        except Exception as e:
            await emitter.error_update(f"Error during TCP service scan on {host}: {str(e)}")
            return str(e)

    def check_port(self, host: str, port: int) -> bool:
        """
        Check if a specific TCP port is open on a host.
        """
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(self.default_timeout)
            result = sock.connect_ex((host, port))
            return result == 0

    async def load_time_measurement(
        self, url: str, __event_emitter__: Callable[[dict], Any] = None
    ) -> str:
        emitter = EventEmitter(__event_emitter__)
        await emitter.progress_update(f"Measuring load time for web page {url}...")

        try:
            start_time = time.time()
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=self.default_timeout) as response:
                    await response.text()  # To actually load the content
            end_time = time.time()
            load_time = end_time - start_time

            await emitter.success_update(f"Load time for {url}: {load_time:.2f} seconds.")
            return f"Load time: {load_time:.2f} seconds"
        except Exception as e:
            await emitter.error_update(f"Error measuring load time for {url}: {str(e)}")
            return str(e)

# Valve functions
async def http_endpoint_check_valve(
    args: HTTPEndpointCheckInput, __event_emitter__: Callable[[dict], Any] = None
) -> str:
    toolkit = WebEndpointToolkit()
    return await toolkit.http_endpoint_check(args.url, __event_emitter__)

async def api_response_validator_valve(
    args: APIResponseValidatorInput, __event_emitter__: Callable[[dict], Any] = None
) -> str:
    toolkit = WebEndpointToolkit()
    return await toolkit.api_response_validator(args.url, args.expected_structure, __event_emitter__)

async def tcp_service_scan_valve(
    args: TCPServiceScannerInput, __event_emitter__: Callable[[dict], Any] = None
) -> str:
    toolkit = WebEndpointToolkit()
    return await toolkit.tcp_service_scan(args.host, args.port_range, __event_emitter__)

async def load_time_measurement_valve(
    args: LoadTimeMeasurementInput, __event_emitter__: Callable[[dict], Any] = None
) -> str:
    toolkit = WebEndpointToolkit()
    return await toolkit.load_time_measurement(args.url, __event_emitter__)

# Pipeline registration
def register_pipelines():
    pipelines = {
        "web_endpoint_diagnostic_pipeline": {
            "description": "Pipeline for web and endpoint diagnostics including HTTP checks, API validation, TCP scanning, and load time measurement.",
            "valves": {
                "http_endpoint_check": {
                    "description": "Check HTTP/HTTPS endpoint status.",
                    "function": "http_endpoint_check_valve",
                    "input_model": "HTTPEndpointCheckInput"
                },
                "api_response_validator": {
                    "description": "Validate API response structure.",
                    "function": "api_response_validator_valve",
                    "input_model": "APIResponseValidatorInput"
                },
                "tcp_service_scan": {
                     "description": "Perform a TCP service scan on a target host.",
                    "function": "tcp_service_scan_valve",
                    "input_model": "TCPServiceScannerInput"
                },
                "load_time_measurement": {
                    "description": "Measure the load time of a web page.",
                    "function": "load_time_measurement_valve",
                    "input_model": "LoadTimeMeasurementInput"
                }
            },
            "filters": [],  # Add any filters if necessary
            "pipes": [],  # Add any pipes if necessary
        }
    }
        }
    return pipelines

# This function is called by OpenWebUI to register pipelines
pipelines = register_pipelines()

# --- Example Usage ---
if __name__ == "__main__":
    import asyncio

    async def test_toolkit():
        # Test HTTP Endpoint Check
        http_result = await http_endpoint_check_valve(
            HTTPEndpointCheckInput(url="https://google.com")
        )
        print(f"HTTP Endpoint Check Result: {http_result}")

        # Test API Response Validator
        api_result = await api_response_validator_valve(
            APIResponseValidatorInput(
                url="https://api.example.com/data",
                expected_structure={"key1": "value1", "key2": "value2"},
            )
        )
        print(f"API Response Validator Result: {api_result}")

        # Test TCP Service Scanner
        tcp_result = await tcp_service_scan_valve(
            TCPServiceScannerInput(host="192.168.1.1", port_range="20-80")
        )
        print(f"TCP Service Scanner Result: {tcp_result}")

        # Test Load Time Measurement
        load_time_result = await load_time_measurement_valve(
            LoadTimeMeasurementInput(url="https://example.com")
        )
        print(f"Load Time Measurement Result: {load_time_result}")

    asyncio.run(test_toolkit())

