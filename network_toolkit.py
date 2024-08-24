"""
title: General Networking Toolkit
author: Phil Dougherty
email: pd@suicidebutton.com
date: 2024-08-24
version: 1.0
license: MIT
description: General tools for networking diagnostics and testing.
"""

import logging
import json
import asyncio
import socket
import python_nmap
import speedtest
from pydantic import BaseModel, Field
from typing import Optional, Callable, Any


# Input models
class NetworkScanInput(BaseModel):
    target: str = Field(
        ...,
        description="The target to scan (IP, hostname, or domain, e.g., '192.168.1.1', 'google.com').",
    )


class SpeedTestInput(BaseModel):
    service: Optional[str] = Field(
        None, description="The speed test service to use (e.g., 'fast', 'ookla')."
    )


# Event emitter class for OpenWebUI
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


# General networking toolkit class
class GeneralNetworkingToolkit:
    def __init__(self):
        self.default_timeout = 5  # Default timeout for network operations in seconds
        self.nm = python_nmap.PortScanner()

    async def execute_command(self, command: list, emitter: EventEmitter) -> str:
        """Executes a shell command and handles errors."""
        try:
            output = (
                subprocess.check_output(
                    command, stderr=subprocess.STDOUT, timeout=self.default_timeout
                )
                .decode("utf-8")
                .strip()
            )
            if not output:
                raise ValueError(f"No output from command: {' '.join(command)}")
            return output
        except subprocess.CalledProcessError as e:
            await emitter.error_update(
                f"Error executing {' '.join(command)}: {e.output.decode('utf-8')}"
            )
            raise
        except IndexError as e:
            await emitter.error_update(
                f"Index error in processing command output: {' '.join(command)}"
            )
            raise

    async def network_scan(self, target: str, __event_emitter__: Callable[[dict], Any] = None) -> str:
        """
        Perform a network scan on the specified target using python-nmap.

        :param target: The target to scan (IP, hostname, or domain).
        :param __event_emitter__: Optional callable for emitting events to OpenWebUI.
        :return: The output of the network scan as JSON.
        """
        emitter = EventEmitter(__event_emitter__)
        await emitter.progress_update(f"Starting network scan for {target}...")

        try:
            scan_result = self.nm.scan(target, arguments='-sP')  # Ping scan
            await emitter.success_update(f"Network scan for {target} complete!")
            return json.dumps(scan_result)
        except Exception as e:
            await emitter.error_update(f"Exception during network scan: {e}")
            return json.dumps({"error": str(e)})

    async def speed_test(self, __event_emitter__: Callable[[dict], Any] = None) -> str:
        """
        Perform an internet speed test using the speedtest-cli module.

        :param __event_emitter__: Optional callable for emitting events to OpenWebUI.
        :return: JSON string containing download, upload speeds, and ping.
        """
        emitter = EventEmitter(__event_emitter__)
        await emitter.progress_update("Running internet speed test...")

        try:
            st = speedtest.Speedtest()
            st.get_best_server()
            download_speed = st.download() / 1_000_000  # Convert to Mbps
            upload_speed = st.upload() / 1_000_000  # Convert to Mbps
            ping = st.results.ping

            results = {
                "Download Speed (Mbps)": download_speed,
                "Upload Speed (Mbps)": upload_speed,
                "Ping (ms)": ping,
            }

            await emitter.success_update("Internet speed test complete!")
            return json.dumps(results)
        except Exception as e:
            await emitter.error_update(f"Error during speed test: {str(e)}")
            return json.dumps({"error": f"Error during speed test: {str(e)}"})


# Function valves
async def network_scan_valve(
    args: NetworkScanInput, __event_emitter__: Callable[[dict], Any] = None
) -> str:
    toolkit = GeneralNetworkingToolkit()
    return await toolkit.network_scan(args.target, __event_emitter__)


async def speed_test_valve(
    args: dict, __event_emitter__: Callable[[dict], Any] = None
) -> str:
    toolkit = GeneralNetworkingToolkit()
    return await toolkit.speed_test(__event_emitter__)


# Register pipelines for OpenWebUI
def register_pipelines():
    """
    Register all pipelines for OpenWebUI to recognize and use.
    """
    pipelines = {
        "network_scan_pipeline": {
            "valves": [network_scan_valve],
            "filters": [],
            "pipes": [],
        },
        "speed_test_pipeline": {
            "valves": [speed_test_valve],
            "filters": [],
            "pipes": [],
        },
    }
    return pipelines


# This function is called by OpenWebUI to register pipelines
pipelines = register_pipelines()
