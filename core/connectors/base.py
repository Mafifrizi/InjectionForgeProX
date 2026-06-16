from abc import ABC, abstractmethod
from typing import List, Dict, Optional

class BaseConnector(ABC):
    @abstractmethod
    def send(self, prompt: str, history: Optional[List[Dict]] = None) -> str:
        pass