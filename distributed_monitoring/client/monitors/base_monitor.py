# monitors/base_monitor.py
from abc import ABC, abstractmethod

class BaseMonitor(ABC):
    """Abstract base class for all monitors."""

    @abstractmethod
    def start(self):
        """Start the monitor."""
        pass
