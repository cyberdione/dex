#!/usr/bin/env python3
"""Check the MCP protocol negotiation used by the production secret resolver."""

import importlib.util
import contextlib
import io
import sys
import types
from pathlib import Path
from unittest import mock


# The resolver imports this exception for its optional boto3 credential path;
# these protocol tests do not make AWS calls or need botocore installed.
botocore = types.ModuleType("botocore")
exceptions = types.ModuleType("botocore.exceptions")
exceptions.BotoCoreError = Exception
botocore.exceptions = exceptions
sys.modules.setdefault("botocore", botocore)
sys.modules.setdefault("botocore.exceptions", exceptions)

source = Path(__file__).with_name("asm-exec.py")
spec = importlib.util.spec_from_file_location("asm_exec", source)
asm_exec = importlib.util.module_from_spec(spec)
spec.loader.exec_module(asm_exec)


def initialize_response(version):
    return {
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "protocolVersion": version,
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "test-server", "version": "1"},
        },
    }


assert asm_exec._initialize_result(initialize_response("2025-06-18")) is not None
assert asm_exec._initialize_result(initialize_response("2024-11-05")) is not None
with contextlib.redirect_stderr(io.StringIO()):
    assert asm_exec._initialize_result(initialize_response("2099-01-01")) is None


class Response:
    headers = {"Mcp-Session-Id": "test-session"}

    @staticmethod
    def read():
        return b"{}"


captured = {}


def capture_request(request, timeout):
    captured["protocol_version"] = request.get_header("Mcp-protocol-version")
    captured["session_id"] = request.get_header("Mcp-session-id")
    return Response()


with mock.patch.object(asm_exec, "_get_aws_credentials", return_value={
    "access_key": "test-access-key",
    "secret_key": "test-secret-key",
    "token": "test-session-token",
}), mock.patch.object(asm_exec.urllib.request, "urlopen", side_effect=capture_request):
    result, session_id = asm_exec._mcp_post(
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
        session_id="test-session",
        protocol_version="2025-06-18",
    )

assert result == {}
assert session_id == "test-session"
assert captured == {
    "protocol_version": "2025-06-18",
    "session_id": "test-session",
}

phase_calls = []


def fake_post(payload, session_id=None, timeout=10, protocol_version=None):
    phase_calls.append((payload, session_id, protocol_version))
    if payload.get("method") == "initialize":
        return initialize_response("2025-06-18"), "negotiated-session"
    if payload.get("method") == "notifications/initialized":
        return {}, None
    return {"jsonrpc": "2.0", "id": 2, "result": {}}, None


with mock.patch.object(asm_exec, "_mcp_post", side_effect=fake_post), mock.patch.object(
    asm_exec, "_extract_run_script_secret", return_value="test-only-value"
):
    resolved = asm_exec._resolve_via_mcp("test-secret-arn", "AWSCURRENT", "us-east-1")

assert resolved == "test-only-value"
assert phase_calls[0][0]["params"]["protocolVersion"] == "2025-06-18"
assert phase_calls[0][1:] == (None, None)
assert phase_calls[1][1:] == ("negotiated-session", "2025-06-18")
assert phase_calls[2][1:] == ("negotiated-session", "2025-06-18")

print("asm-exec MCP protocol negotiation tests passed")
