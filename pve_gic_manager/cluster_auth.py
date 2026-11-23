"""
Proxmox VE Cluster Node Authentication & Inter-Node Communication
"""
import os
import hmac
import hashlib
import secrets
import json
import logging
import urllib.request
import urllib.error
from .config import cfg

logger = logging.getLogger("pve_gic_auth")

def ensure_cluster_token():
    """Ensure a strong cluster shared token exists, generate if missing."""
    token = cfg.cluster_token
    if not token or len(token) < 16:
        token = secrets.token_hex(32) # 64-character hex token
        cfg.set_cluster_token(token)
        logger.info("Generated new cluster shared token")
    return token

def verify_token(provided_token):
    """Secure constant-time verification of node token."""
    expected = cfg.cluster_token
    if not expected:
        expected = ensure_cluster_token()
    if not provided_token:
        return False
    # Support 'Bearer <token>' or raw token
    if provided_token.startswith("Bearer "):
        provided_token = provided_token[7:].strip()
    return hmac.compare_digest(expected.strip(), provided_token.strip())

def get_auth_headers():
    token = ensure_cluster_token()
    return {
        "X-Node-Token": token,
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

def call_node_api(node_ip, port=8004, endpoint="/api/v1/health", method="GET", payload=None, timeout=3.0):
    """
    Execute authenticated API call to another PVE cluster node.
    """
    if endpoint.startswith("/"):
        endpoint = endpoint[1:]
    url = f"http://{node_ip}:{port}/{endpoint}"
    headers = get_auth_headers()
    
    data = None
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")

    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8")
            return {
                "success": True,
                "status_code": resp.status,
                "data": json.loads(body) if body else {}
            }
    except urllib.error.HTTPError as e:
        err_body = e.read().decode("utf-8", errors="replace")
        logger.warning(f"Node API HTTP {e.code} from {url}: {err_body}")
        try:
            err_data = json.loads(err_body)
        except Exception:
            err_data = {"error": err_body}
        return {
            "success": False,
            "status_code": e.code,
            "error": f"HTTP {e.code}: {e.reason}",
            "data": err_data
        }
    except Exception as e:
        logger.warning(f"Failed to connect to node {node_ip}:{port}: {e}")
        return {
            "success": False,
            "status_code": 0,
            "error": str(e),
            "data": None
        }
