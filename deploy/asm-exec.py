#!/usr/bin/env python3
"""asm-exec: Resolve {{resolve:secretsmanager:...}} references and run the command.

Usage: asm-exec <command> [args...]

Resolves dynamic references in arguments and exported environment variables,
then runs the command. Secret values never return to the calling agent.

Resolution order:
  1. AWS Secrets Manager Agent (SMA) on localhost:2773 (zero-latency, cached)
  2. Streamable HTTP MCP endpoint (requires AWS credentials)

Security: Uses re.sub with callable for single-pass substitution (resolved
values are never re-scanned). SecretBinary is not supported.
"""

import datetime
import hashlib
import hmac
import http.client
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request

from botocore.exceptions import BotoCoreError


PATTERN = re.compile(r'\{\{resolve:secretsmanager:([^}]+)\}\}')
SMA_ENDPOINT = os.environ.get('AWS_SECRETS_MANAGER_AGENT_ENDPOINT', 'http://localhost:2773')
SSRF_TOKEN = os.environ.get('AWS_SESSION_TOKEN', os.environ.get('AWS_TOKEN', ''))
MCP_ENDPOINT = os.environ.get('ASM_EXEC_MCP_ENDPOINT', 'https://aws-mcp.us-east-1.api.aws/mcp')
MAX_STDIN_REFERENCE_BYTES = 64 * 1024

_sma_available = None


def _check_sma():
    global _sma_available
    if _sma_available is None:
        try:
            req = urllib.request.Request(f'{SMA_ENDPOINT}/ping', method='GET')
            urllib.request.urlopen(req, timeout=1)
            _sma_available = True
        except (urllib.error.URLError, OSError):
            _sma_available = False
    return _sma_available


def _get_aws_credentials():
    """Resolve AWS credentials for SigV4 signing.

    Order: environment variables, standard boto3 credential chain (including
    ECS task-role container credentials), then AWS CLI configuration fallbacks.
    Returns a dict with access_key/secret_key/token or None.
    """
    if os.environ.get('AWS_ACCESS_KEY_ID'):
        return {
            'access_key': os.environ['AWS_ACCESS_KEY_ID'],
            'secret_key': os.environ.get('AWS_SECRET_ACCESS_KEY', ''),
            'token': os.environ.get('AWS_SESSION_TOKEN', ''),
        }
    # Fargate task roles expose short-lived credentials through the ECS
    # container metadata provider, not AWS_ACCESS_KEY_ID environment variables.
    # boto3's standard chain reads that provider without a direct secret API
    # call and without requiring an AWS CLI in this image.
    try:
        import boto3
        frozen = boto3.Session().get_credentials()
        if frozen:
            frozen = frozen.get_frozen_credentials()
            if frozen.access_key:
                return {
                    'access_key': frozen.access_key,
                    'secret_key': frozen.secret_key,
                    'token': frozen.token or '',
                }
    except BotoCoreError:
        # The following CLI fallbacks remain useful for non-ECS local runs.
        pass
    # AWS CLI v2: export-credentials emits resolved (possibly assumed-role) creds.
    try:
        result = subprocess.run(
            ['aws', 'configure', 'export-credentials', '--format', 'env'],
            capture_output=True, text=True, check=True, timeout=5
        )
        creds = {}
        for line in result.stdout.splitlines():
            if '=' in line:
                line = line.removeprefix('export ')
                k, v = line.split('=', 1)
                if k == 'AWS_ACCESS_KEY_ID':
                    creds['access_key'] = v
                elif k == 'AWS_SECRET_ACCESS_KEY':
                    creds['secret_key'] = v
                elif k == 'AWS_SESSION_TOKEN':
                    creds['token'] = v
        if creds.get('access_key'):
            return creds
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
        pass
    # AWS CLI v1 fallback: read static creds from the configured profile.
    try:
        def _cfg(key):
            r = subprocess.run(['aws', 'configure', 'get', key],
                               capture_output=True, text=True, timeout=5)
            return r.stdout.strip() if r.returncode == 0 else ''
        access_key = _cfg('aws_access_key_id')
        if access_key:
            return {
                'access_key': access_key,
                'secret_key': _cfg('aws_secret_access_key'),
                'token': _cfg('aws_session_token'),
            }
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return None


def _signing_service_region(endpoint):
    """Derive (service, region) for SigV4 from an AWS MCP endpoint hostname.

    Mirrors mcp-proxy-for-aws: 'service.region.api.aws' -> (service, region);
    'bedrock-agentcore' style is handled as a special case. The signing region
    is the endpoint's own region, independent of any secret's region.
    """
    host = urllib.parse.urlparse(endpoint).hostname or ''
    parts = host.split('.')
    if len(parts) >= 5 and parts[-4] == 'bedrock-agentcore' and parts[-2:] == ['amazonaws', 'com']:
        return 'bedrock-agentcore', parts[-3]
    if len(parts) == 4 and parts[2:] == ['api', 'aws']:
        return parts[0], parts[1]
    # Fallback: first segment as service, region from environment.
    region = os.environ.get('AWS_REGION') or os.environ.get('AWS_DEFAULT_REGION') or 'us-east-1'
    return (parts[0] if parts else 'aws-mcp'), region


def _sign_v4(method, path, body, creds, service, region, now):
    """Compute SigV4 headers (stdlib only) for a request. Returns a header dict.

    botocore is not available in asm-exec's runtime, so signing is implemented
    directly with hashlib/hmac following the AWS SigV4 spec.
    """
    host = urllib.parse.urlparse(MCP_ENDPOINT).hostname or ''
    amzdate = now.strftime('%Y%m%dT%H%M%SZ')
    datestamp = now.strftime('%Y%m%d')
    payload_hash = hashlib.sha256(body).hexdigest()

    headers = {
        'host': host,
        'x-amz-date': amzdate,
        'x-amz-content-sha256': payload_hash,
    }
    if creds.get('token'):
        headers['x-amz-security-token'] = creds['token']

    signed_keys = sorted(headers)
    canonical_headers = ''.join(f'{k}:{headers[k].strip()}\n' for k in signed_keys)
    signed_headers_str = ';'.join(signed_keys)
    canonical_request = (f'{method}\n{path}\n\n{canonical_headers}\n'
                         f'{signed_headers_str}\n{payload_hash}')

    scope = f'{datestamp}/{region}/{service}/aws4_request'
    string_to_sign = (f'AWS4-HMAC-SHA256\n{amzdate}\n{scope}\n'
                      f'{hashlib.sha256(canonical_request.encode()).hexdigest()}')

    def _hmac(key, msg):
        return hmac.new(key, msg.encode('utf-8'), hashlib.sha256).digest()

    k_date = _hmac(('AWS4' + creds['secret_key']).encode('utf-8'), datestamp)
    k_region = _hmac(k_date, region)
    k_service = _hmac(k_region, service)
    k_signing = _hmac(k_service, 'aws4_request')
    signature = hmac.new(k_signing, string_to_sign.encode('utf-8'),
                         hashlib.sha256).hexdigest()

    headers['Authorization'] = (
        f'AWS4-HMAC-SHA256 Credential={creds["access_key"]}/{scope}, '
        f'SignedHeaders={signed_headers_str}, Signature={signature}'
    )
    return headers


def _mcp_post(payload, session_id=None, timeout=10):
    """POST a SigV4-signed JSON-RPC request to the AWS MCP endpoint.

    Returns (parsed_response, session_id_from_response). The caller passes the
    session id returned by 'initialize' back into subsequent calls.
    """
    creds = _get_aws_credentials()
    if not creds or not creds.get('access_key'):
        raise RuntimeError('no AWS credentials available for MCP signing')

    body = json.dumps(payload).encode()
    service, region = _signing_service_region(MCP_ENDPOINT)
    path = urllib.parse.urlparse(MCP_ENDPOINT).path or '/'
    now = datetime.datetime.utcnow()

    sig_headers = _sign_v4('POST', path, body, creds, service, region, now)
    req = urllib.request.Request(MCP_ENDPOINT, data=body, method='POST')
    req.add_header('Content-Type', 'application/json')
    req.add_header('Accept', 'application/json, text/event-stream')
    req.add_header('User-Agent', 'ASMExecWrapper/1.0.0')
    if session_id:
        req.add_header('Mcp-Session-Id', session_id)
    for k, v in sig_headers.items():
        req.add_header(k, v)

    resp = urllib.request.urlopen(req, timeout=timeout)
    session_out = resp.headers.get('Mcp-Session-Id')
    raw = resp.read()
    parsed = json.loads(raw) if raw else {}
    return parsed, session_out


def _mcp_failure(phase, failure_class, *, status=None, reason=None):
    """Emit a fixed diagnostic without serializing endpoint responses or errors."""
    fields = [
        "asm-exec: MCP resolution failed",
        f"phase={phase}",
        f"class={failure_class}",
    ]
    if status is not None:
        fields.append(f"status={status}")
    if reason is not None:
        fields.append(f"reason={reason}")
    print(" ".join(fields), file=sys.stderr)


def _mcp_phase_call(phase, payload, session_id=None):
    """Call one MCP protocol phase and expose only fixed failure metadata."""
    try:
        # run_script legitimately executes an AWS API inside the MCP sandbox.
        # Keep handshake phases short while giving that bounded read time to return.
        timeout = 60 if phase == "tools-call" else 10
        return _mcp_post(payload, session_id, timeout=timeout)
    except urllib.error.HTTPError as exc:
        # Deliberately do not read exc.fp or print its message: either can carry
        # an API response body or request context.
        _mcp_failure(phase, "http", status=exc.code)
        exc.close()
    except json.JSONDecodeError:
        _mcp_failure(phase, "protocol")
    except (urllib.error.URLError, OSError, http.client.HTTPException):
        _mcp_failure(phase, "transport")
    except RuntimeError:
        _mcp_failure(phase, "credentials")
    except (KeyError, TypeError, ValueError):
        _mcp_failure(phase, "protocol")
    return None


def _mcp_request_result(phase, response, expected_id):
    """Accept exactly one well-formed JSON-RPC success response."""
    if not isinstance(response, dict):
        _mcp_failure(phase, "protocol")
        return None
    if response.get("jsonrpc") != "2.0" or type(response.get("id")) is not int or response.get("id") != expected_id:
        _mcp_failure(phase, "protocol")
        return None
    has_result = "result" in response
    has_error = "error" in response
    if has_result == has_error:
        _mcp_failure(phase, "protocol")
        return None
    if has_error:
        _mcp_failure(phase, "response", reason="jsonrpc_error")
        return None
    return response["result"]


def _initialize_result(response):
    """Validate the legacy handshake result before sending any later phase."""
    result = _mcp_request_result("initialize", response, 1)
    if not isinstance(result, dict):
        if result is not None:
            _mcp_failure("initialize", "protocol")
        return None
    if result.get("protocolVersion") != "2024-11-05":
        _mcp_failure("initialize", "protocol")
        return None
    capabilities = result.get("capabilities")
    server_info = result.get("serverInfo")
    if not (_valid_server_capabilities(capabilities)
            and isinstance(server_info, dict)
            and isinstance(server_info.get("name"), str)
            and isinstance(server_info.get("version"), str)
            and ("instructions" not in result or isinstance(result["instructions"], str))
            and ("_meta" not in result or isinstance(result["_meta"], dict))):
        _mcp_failure("initialize", "protocol")
        return None
    return result


def _valid_server_capabilities(capabilities):
    """Validate the 2024-11-05 known capability shapes, retaining extensions."""
    if not isinstance(capabilities, dict) or not isinstance(capabilities.get("tools"), dict):
        return False
    for name in ("experimental", "logging"):
        if name in capabilities and not isinstance(capabilities[name], dict):
            return False
    experimental = capabilities.get("experimental", {})
    if any(not isinstance(value, dict) for value in experimental.values()):
        return False
    for name, boolean_fields in {
        "prompts": ("listChanged",),
        "resources": ("subscribe", "listChanged"),
        "tools": ("listChanged",),
    }.items():
        if name not in capabilities:
            continue
        value = capabilities[name]
        if not isinstance(value, dict):
            return False
        if any(field in value and type(value[field]) is not bool for field in boolean_fields):
            return False
    return True


def _notification_accepted(response):
    """Allow the documented empty successful notification response only."""
    if response == {}:
        return True
    _mcp_failure("notify", "protocol" if not isinstance(response, dict) or "error" not in response else "response",
                 reason="jsonrpc_error" if isinstance(response, dict) and "error" in response else None)
    return False


def _run_script_envelope(response):
    """Validate one structured run_script success envelope without logging it."""
    if not isinstance(response, dict) or "error" in response:
        _mcp_failure("extract", "protocol")
        return None
    result = response.get("result")
    if not isinstance(result, dict):
        _mcp_failure("extract", "response", reason="secret_missing")
        return None
    if result.get("isError") is not False:
        _mcp_failure("extract", "response", reason="run_script_unsuccessful")
        return None

    structured = result.get("structuredContent")
    content = result.get("content")
    if not isinstance(structured, dict) or not isinstance(content, list) or len(content) != 1:
        _mcp_failure("extract", "protocol")
        return None
    item = content[0]
    if not isinstance(item, dict) or item.get("type") != "text" or not isinstance(item.get("text"), str):
        _mcp_failure("extract", "protocol")
        return None
    try:
        text_envelope = json.loads(item["text"])
    except json.JSONDecodeError:
        _mcp_failure("extract", "protocol")
        return None
    if not isinstance(text_envelope, dict):
        _mcp_failure("extract", "protocol")
        return None
    # MCP returns both a structured and textual representation. They must agree
    # on the security-relevant fields; otherwise reject the ambiguous response.
    for key in ("status", "api_calls", "return_value"):
        if text_envelope.get(key) != structured.get(key):
            _mcp_failure("extract", "protocol")
            return None
    return structured


def _expected_get_secret_value_call(call):
    """Match the one successful Secrets Manager call made by run_script."""
    return (isinstance(call, dict) and
            call.get("service") == "secretsmanager" and
            call.get("operation") == "GetSecretValue" and
            call.get("status") == "success")


def _extract_run_script_secret(response, expected_secret_arn=None):
    """Require one verified GetSecretValue envelope before accepting SecretString."""
    envelope = _run_script_envelope(response)
    if envelope is None:
        return None
    if envelope.get("status") != "success":
        _mcp_failure("extract", "response", reason="run_script_unsuccessful")
        return None

    api_calls = envelope.get("api_calls")
    if not isinstance(api_calls, list) or len(api_calls) != 1 or not _expected_get_secret_value_call(api_calls[0]):
        _mcp_failure("extract", "response", reason="expected_api_missing")
        return None

    return_value = envelope.get("return_value")
    if not isinstance(return_value, dict):
        _mcp_failure("extract", "response", reason="secret_missing")
        return None
    if expected_secret_arn is not None and return_value.get("ARN") != expected_secret_arn:
        _mcp_failure("extract", "response", reason="secret_missing")
        return None
    secret = return_value.get("SecretString")
    if not isinstance(secret, str) or not secret:
        _mcp_failure("extract", "response", reason="secret_missing")
        return None
    return secret


def _run_script_code(secret_name, label, region):
    """Build literal-safe Python for the remote MCP sandbox, never local SDK use."""
    params_json = json.dumps({"SecretId": secret_name, "VersionStage": label}, sort_keys=True)
    region_json = json.dumps(region)
    return "\n".join((
        "result = await call_boto3(",
        "    service_name=\"secretsmanager\",",
        "    operation_name=\"GetSecretValue\",",
        f"    region_name=json.loads({json.dumps(region_json)}),",
        f"    params=json.loads({json.dumps(params_json)}),",
        ")",
        "result",
    ))


def _resolve_via_mcp(secret_name, label, region):
    """Resolve through the runtime MCP sandbox with fixed, non-secret failures."""
    initialized = _mcp_phase_call(
        "initialize",
        {"jsonrpc": "2.0", "id": 1, "method": "initialize",
         "params": {"protocolVersion": "2024-11-05",
                    "clientInfo": {"name": "asm-exec", "version": "1.0.0"},
                    "capabilities": {}}},
    )
    if initialized is None:
        return None
    initialize_response, session_id = initialized
    if _initialize_result(initialize_response) is None:
        return None

    notified = _mcp_phase_call(
        "notify",
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        session_id,
    )
    if notified is None:
        return None
    notification_response, _ = notified
    if not _notification_accepted(notification_response):
        return None

    called = _mcp_phase_call(
        "tools-call",
        {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
         "params": {"name": "aws___run_script",
                    "arguments": {"code": _run_script_code(secret_name, label, region)}}},
        session_id,
    )
    if called is None:
        return None
    response, _ = called
    if _mcp_request_result("tools-call", response, 2) is None:
        return None
    return _extract_run_script_secret(
        response, secret_name if secret_name.startswith("arn:") else None
    )


def resolve_one(ref):
    """Resolve secret-id[:field-type[:json-key[:version-stage]]].

    Secret-id may be an ARN (contains colons) or a plain name.
    ARN format: arn:aws:secretsmanager:<Region>:<AccountId>:secret:<SecretName>-<6RandomChars>
    """
    # ARN-aware split: if ref starts with 'arn:', treat everything up to
    # the 7th colon as the secret-id (6 colons in a standard ARN)
    if ref.startswith('arn:'):
        arn_parts = ref.split(':')
        # Standard ARN has 7 segments (indices 0-6): arn:partition:service:region:account:resource-type:resource-id
        if len(arn_parts) >= 7:
            secret_name = ':'.join(arn_parts[:7])
            remainder = arn_parts[7:]
        else:
            secret_name = ref
            remainder = []
        field_type = remainder[0] if len(remainder) > 0 else 'SecretString'
        json_key = remainder[1] if len(remainder) > 1 else None
        label = remainder[2] if len(remainder) > 2 else 'AWSCURRENT'
    else:
        parts = ref.split(':', 3)
        secret_name = parts[0]
        field_type = parts[1] if len(parts) > 1 else 'SecretString'
        json_key = parts[2] if len(parts) > 2 else None
        label = parts[3] if len(parts) > 3 else 'AWSCURRENT'

    if field_type != 'SecretString':
        print(f'asm-exec: ERROR: Only SecretString is supported, got: {field_type}', file=sys.stderr)
        sys.exit(1)

    value = None

    # Region for cross-region secrets: honor an ARN's region segment first,
    # then fall back to the ambient AWS_REGION / AWS_DEFAULT_REGION.
    region = None
    if secret_name.startswith('arn:'):
        arn_segments = secret_name.split(':')
        if len(arn_segments) >= 4 and arn_segments[3]:
            region = arn_segments[3]
    if not region:
        region = os.environ.get('AWS_REGION') or os.environ.get('AWS_DEFAULT_REGION')

    # 1. Try SMA daemon
    if _check_sma():
        url = f'{SMA_ENDPOINT}/secretsmanager/get?secretId={urllib.parse.quote(secret_name, safe="")}&versionStage={label}'
        req = urllib.request.Request(url, method='GET')
        if SSRF_TOKEN:
            req.add_header('X-Aws-Parameters-Secrets-Token', SSRF_TOKEN)
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read())
                value = data.get('SecretString')
        except (urllib.error.URLError, OSError, json.JSONDecodeError):
            pass

    # 2. Resolve via Streamable HTTP MCP
    if not value:
        value = _resolve_via_mcp(secret_name, label, region)

    if not value:
        print('asm-exec: ERROR: Failed to resolve secret reference', file=sys.stderr)
        sys.exit(1)

    if json_key:
        try:
            obj = json.loads(value)
            value = obj[json_key]
        except (json.JSONDecodeError, KeyError, TypeError):
            print('asm-exec: ERROR: JSON key unavailable in resolved secret', file=sys.stderr)
            sys.exit(1)
        if not isinstance(value, str):
            value = json.dumps(value)

    return value


def resolve_string(s):
    """Single-pass substitution — resolved values are never re-scanned."""
    return PATTERN.sub(lambda m: resolve_one(m.group(1)), s)


def _usage():
    print('Usage: asm-exec [--stdin-reference {{resolve:secretsmanager:...}} --] <command> [args...]', file=sys.stderr)


def main():
    if len(sys.argv) < 2:
        _usage()
        sys.exit(1)

    cmd_args = sys.argv[1:]
    # Retain the normal `asm-exec -- command` form for existing callers.
    if cmd_args and cmd_args[0] == '--':
        cmd_args = cmd_args[1:]

    stdin_reference = None
    if cmd_args and cmd_args[0] == '--stdin-reference':
        if len(cmd_args) < 4 or cmd_args[2] != '--':
            _usage()
            sys.exit(1)
        reference = cmd_args[1]
        match = PATTERN.fullmatch(reference)
        if match is None:
            print('asm-exec: ERROR: stdin reference must be one complete Secrets Manager dynamic reference', file=sys.stderr)
            sys.exit(1)
        # This explicit path resolves the reference once and never places the
        # value in child argv or environment. `input=` gives the child a pipe.
        try:
            resolved = resolve_one(match.group(1))
            if not isinstance(resolved, str):
                raise ValueError("resolved stdin value is not text")
            stdin_reference = resolved.encode('utf-8')
        except (UnicodeError, ValueError, TypeError):
            print('asm-exec: ERROR: stdin reference could not be prepared', file=sys.stderr)
            sys.exit(1)
        if not stdin_reference or len(stdin_reference) > MAX_STDIN_REFERENCE_BYTES:
            print('asm-exec: ERROR: stdin reference exceeds the reviewed size limit', file=sys.stderr)
            sys.exit(1)
        cmd_args = cmd_args[3:]

    if not cmd_args:
        _usage()
        sys.exit(1)

    args = [resolve_string(a) if PATTERN.search(a) else a for a in cmd_args]
    if stdin_reference is None:
        result = subprocess.run(args)
    else:
        # The provisioning child receives the reference only through a pipe.
        # Capture its streams so a mistaken raw echo cannot become a task log.
        result = subprocess.run(args, input=stdin_reference, capture_output=True)
        stdout = result.stdout if isinstance(result.stdout, bytes) else b""
        stderr = result.stderr if isinstance(result.stderr, bytes) else b""
        if stdin_reference in stdout or stdin_reference in stderr:
            print('asm-exec: ERROR: child emitted the resolved stdin reference', file=sys.stderr)
            sys.exit(1)
        if stdout:
            sys.stdout.buffer.write(stdout)
            sys.stdout.buffer.flush()
        if stderr:
            sys.stderr.buffer.write(stderr)
            sys.stderr.buffer.flush()
    sys.exit(result.returncode)


if __name__ == '__main__':
    main()
