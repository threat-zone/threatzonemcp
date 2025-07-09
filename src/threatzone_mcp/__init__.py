"""Threat.Zone MCP Server package."""

__version__ = "0.1.0"
__author__ = "Malwation Team"
__email__ = "info@malwation.com"

from .server import app, main

__all__ = ["app", "main", "__version__"] 