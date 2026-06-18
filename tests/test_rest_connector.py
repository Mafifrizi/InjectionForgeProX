import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import responses
from core.connectors.rest import RESTChatbotConnector
import json

@responses.activate
def test_send_with_headers():
    responses.add(
        responses.POST,
        "http://test.local/api",
        json={"reply": "OK"},
        status=200
    )
    conn = RESTChatbotConnector(
        endpoint="http://test.local/api",
        headers={"X-API-Key": "secret"}
    )
    resp = conn.send("halo")
    assert resp == "OK"
    # Cek header yang dikirim
    req_headers = responses.calls[0].request.headers
    assert req_headers["X-API-Key"] == "secret"