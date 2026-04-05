from abc import ABC, abstractmethod
from typing import List

from models.interface import InterfaceResult


class BaseCollector(ABC):
    """
    Every platform collector inherits from this.

    To add a new platform (e.g. Cisco, F5):
      1. Create collectors/cisco.py (or f5.py, etc.)
      2. Subclass BaseCollector
      3. Implement collect()
      4. Register it in collectors/__init__.py
    """

    def __init__(self, hostname: str, ip_address: str, username: str, password: str,
                 verify_ssl: bool = False):
        self.hostname = hostname
        self.ip_address = ip_address
        self.username = username
        self.password = password
        self.verify_ssl = verify_ssl

    @abstractmethod
    def collect(self) -> List[InterfaceResult]:
        """
        Connect to the device and return a list of InterfaceResult objects —
        one per interface. On total failure, return a single InterfaceResult
        with error populated so the output layer can report it cleanly.
        """
        pass

    def _error_result(self, error_msg: str) -> List[InterfaceResult]:
        """Convenience: wrap a connection/auth error into the standard result."""
        return [InterfaceResult(
            hostname=self.hostname,
            device_ip=self.ip_address,
            platform=self.__class__.__name__,
            interface_name="N/A",
            ipv4_address="N/A",
            ipv6_addresses=[],
            error=error_msg,
        )]
