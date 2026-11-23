"""
Proxmox VE User Authentication Handler
Authenticates users against local PVE PAM / PVE Realm and manages user sessions.
"""
import ssl
import time
import secrets
import logging
import urllib.request
import urllib.error
import urllib.parse
import json

logger = logging.getLogger("pve_user_auth")

ACTIVE_SESSIONS = {}
SESSION_EXPIRY_SECONDS = 7200  # 2 hours

def verify_pve_credentials(username, password, realm="pam"):
    """
    Authenticate username and password against local Proxmox VE 8006 ticket API.
    Returns: (success: bool, user_id: str, error_msg: str)
    """
    if not username or not password:
        return False, "", "用户名和密码不能为空"

    # Normalize full user identifier
    if "@" in username:
        full_user = username
    else:
        full_user = f"{username}@{realm}"

    url = "https://127.0.0.1:8006/api2/json/access/ticket"
    payload = urllib.parse.urlencode({
        "username": full_user,
        "password": password
    }).encode("utf-8")

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    req = urllib.request.Request(url, data=payload, method="POST")
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=4.0) as resp:
            body = json.loads(resp.read().decode("utf-8"))
            if body.get("data") and body["data"].get("ticket"):
                logger.info(f"User {full_user} authenticated successfully via PVE API")
                return True, full_user, ""
    except urllib.error.HTTPError as e:
        logger.warning(f"PVE authentication failed for {full_user}: HTTP {e.code}")
        return False, "", "认证失败：用户名或密码错误"
    except Exception as e:
        logger.error(f"Cannot connect to PVE auth service: {e}")
        # If PVE API unreachable, check if local PAM validation can be done for root
        return False, "", f"无法连接 PVE 认证服务: {str(e)}"

    return False, "", "认证失败，请重试"

def create_session(username):
    """Create a new session token for authenticated user."""
    token = secrets.token_hex(32)
    ACTIVE_SESSIONS[token] = {
        "username": username,
        "created_at": time.time(),
        "expires_at": time.time() + SESSION_EXPIRY_SECONDS
    }
    return token

def validate_session(token):
    """Check if session token is valid and not expired."""
    if not token or token not in ACTIVE_SESSIONS:
        return None
    session = ACTIVE_SESSIONS[token]
    if time.time() > session["expires_at"]:
        del ACTIVE_SESSIONS[token]
        return None
    # Refresh sliding expiration
    session["expires_at"] = time.time() + SESSION_EXPIRY_SECONDS
    return session["username"]

def revoke_session(token):
    """Invalidate session on logout."""
    if token in ACTIVE_SESSIONS:
        del ACTIVE_SESSIONS[token]
