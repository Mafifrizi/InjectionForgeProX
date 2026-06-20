from abc import ABC, abstractmethod
from typing import List, Dict, Optional


class BaseConnector(ABC):
    """Target connector contract.

    ``send`` returns a successful target response only. Transport failures must
    be raised (normally ``requests.RequestException`` or
    ``core.transport.TransportError``) so the shared retry layer can apply
    rate limiting, Retry-After, exponential backoff, and typed failure
    reporting consistently.
    """

    @abstractmethod
    def send(self, prompt: str, history: Optional[List[Dict]] = None) -> str:
        pass
