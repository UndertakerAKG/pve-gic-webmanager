"""
Proxmox VE Node API Service (Port 8004)
Handles authenticated cluster communication, user login authentication, VM inspection, and GIC updates.
"""
import json
import logging
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
import urllib.parse
from .config import cfg
from .cluster_auth import verify_token, ensure_cluster_token
from .auth_handler import verify_pve_credentials, create_session, validate_session, revoke_session
from .pve_scanner import scanner
from . import history_manager

logger = logging.getLogger("pve_gic_api")

class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = True

class NodeAPIHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        logger.debug(f"{self.client_address[0]} - {format % args}")

    def send_json(self, status_code, data, set_cookie=None):
        body = json.dumps(data, ensure_ascii=False, indent=2).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Node-Token, X-User-Session")
        if set_cookie:
            self.send_header("Set-Cookie", set_cookie)
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Node-Token, X-User-Session")
        self.end_headers()

    def get_session_token(self):
        """Extract user session token from header or cookie."""
        token = self.headers.get("X-User-Session")
        if token:
            return token.strip()
        cookie_header = self.headers.get("Cookie", "")
        for part in cookie_header.split(";"):
            part = part.strip()
            if part.startswith("pve_session="):
                return part[12:].strip()
        return None

    def get_current_user(self):
        """Extract logged-in username or cluster identity."""
        token = self.get_session_token()
        if token:
            user = validate_session(token)
            if user:
                return user
        node_token = self.headers.get("X-Node-Token")
        if node_token and verify_token(node_token):
            return "system@cluster"
        return "root@pam"
        """Extract user session token from header or cookie."""
        token = self.headers.get("X-User-Session")
        if token:
            return token.strip()
        cookie_header = self.headers.get("Cookie", "")
        for part in cookie_header.split(";"):
            part = part.strip()
            if part.startswith("pve_session="):
                return part[12:].strip()
        return None

    def check_auth(self):
        """
        Verify request authorization:
        Pass if:
          1. Public endpoint (/api/v1/health, /api/v1/auth/login, /api/v1/auth/status, /api/v1/auth/logout)
          2. Valid cluster node token (X-Node-Token)
          3. Valid logged-in user session (X-User-Session / Cookie)
        """
        path = self.path.split("?")[0].rstrip('/')
        if path in ["/api/v1/health", "/api/v1/version", "/api/v1/auth/login", "/api/v1/auth/status", "/api/v1/auth/logout"]:
            return True

        # Check Node-to-Node Token
        node_token = self.headers.get("X-Node-Token")
        if not node_token:
            auth_header = self.headers.get("Authorization", "")
            if auth_header.startswith("Bearer "):
                node_token = auth_header[7:].strip()

        if node_token and verify_token(node_token):
            return True

        # Check User Session (Requirement 4)
        session_token = self.get_session_token()
        if session_token:
            user = validate_session(session_token)
            if user:
                return True

        logger.warning(f"Unauthorized API request from {self.client_address[0]} to {self.path}")
        return False

    def do_GET(self):
        if not self.check_auth():
            return self.send_json(401, {"error": "Unauthorized: 必须先登录或提供节点认证令牌", "auth_required": True})

        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path.rstrip('/')
        query_params = urllib.parse.parse_qs(parsed_url.query)

        # 1. Health check
        if path == "/api/v1/health":
            return self.send_json(200, {
                "status": "healthy",
                "service": "pve-gic-api",
                "node": scanner.local_node_name,
                "node_ip": scanner.local_node_ip,
                "port": cfg.api_port
            })

        # Dedicated System PVE Version Endpoint (Dynamic from Host System)
        elif path == "/api/v1/version":
            info = scanner.get_pve_version_info()
            return self.send_json(200, {
                "success": True,
                "node": scanner.local_node_name,
                **info
            })

        # 2. Auth status check (Requirement 4)
        elif path == "/api/v1/auth/status":
            session_token = self.get_session_token()
            user = validate_session(session_token) if session_token else None
            return self.send_json(200, {
                "authenticated": bool(user),
                "username": user or "",
                "local_node": scanner.local_node_name,
                "local_ip": scanner.local_node_ip,
                "pve_version": scanner.get_pve_version()
            })

        # 3. Node info
        elif path == "/api/v1/node/info":
            return self.send_json(200, {
                "node_name": scanner.local_node_name,
                "node_ip": scanner.local_node_ip,
                "is_cluster": len(scanner.get_cluster_nodes()) > 1,
                "cluster_nodes_count": len(scanner.get_cluster_nodes()),
                "pve_version": scanner.get_pve_version()
            })

        # 4. Cluster Nodes
        elif path == "/api/v1/cluster/nodes":
            nodes = scanner.get_cluster_nodes()
            return self.send_json(200, {
                "success": True,
                "nodes": nodes
            })

        # 5. List VMs
        elif path == "/api/v1/vms":
            local_only = query_params.get("local_only", ["0"])[0] == "1"
            filter_node = query_params.get("node", [None])[0]

            if local_only:
                vms = scanner.scan_local_vms()
            else:
                vms = scanner.scan_all_vms()

            if filter_node:
                vms = {k: v for k, v in vms.items() if v.get("node") == filter_node}

            nodes = scanner.get_cluster_nodes()
            return self.send_json(200, {
                "success": True,
                "cluster_name": scanner.get_cluster_name(),
                "total": len(vms),
                "nodes": nodes,
                "vms": vms,
                "pve_version": scanner.get_pve_version()
            })

        # 6. Single VM info
        elif path.startswith("/api/v1/vms/"):
            parts = path.split("/")
            if len(parts) >= 5 and parts[4].isdigit():
                vmid = int(parts[4])
                all_vms = scanner.scan_all_vms()
                vm_info = all_vms.get(vmid)
                if vm_info:
                    return self.send_json(200, {"success": True, "vm": vm_info})
                else:
                    return self.send_json(404, {"error": f"VM {vmid} not found"})

        # 7. Operation Audit History (Permanent Log)
        elif path == "/api/v1/history":
            user = self.get_current_user()
            limit = int(query_params.get("limit", ["200"])[0])
            records = history_manager.get_records(limit=limit)
            return self.send_json(200, {
                "success": True,
                "history": records,
                "is_root": history_manager.is_root_user(user),
                "current_user": user
            })

        self.send_json(404, {"error": f"Endpoint not found: {path}"})

    def do_POST(self):
        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path.rstrip('/')

        # Read JSON body
        content_length = int(self.headers.get("Content-Length", 0))
        body_data = {}
        if content_length > 0:
            raw_body = self.rfile.read(content_length).decode("utf-8")
            try:
                body_data = json.loads(raw_body)
            except Exception:
                return self.send_json(400, {"error": "Invalid JSON body"})

        # 1. User Login (Requirement 4: Same as PVE Login)
        if path == "/api/v1/auth/login":
            username = body_data.get("username", "").strip()
            password = body_data.get("password", "")
            realm = body_data.get("realm", "pam").strip()

            success, full_user, err_msg = verify_pve_credentials(username, password, realm)
            if success:
                token = create_session(full_user)
                cookie_str = f"pve_session={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=7200"
                return self.send_json(200, {
                    "success": True,
                    "username": full_user,
                    "session_token": token,
                    "local_node": scanner.local_node_name,
                    "local_ip": scanner.local_node_ip,
                    "message": "登录成功"
                }, set_cookie=cookie_str)
            else:
                return self.send_json(401, {
                    "success": False,
                    "error": err_msg or "认证失败：用户名或密码错误"
                })

        # 2. User Logout
        elif path == "/api/v1/auth/logout":
            token = self.get_session_token()
            if token:
                revoke_session(token)
            cookie_str = "pve_session=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT"
            return self.send_json(200, {"success": True, "message": "已成功退出登录"}, set_cookie=cookie_str)

        # Check authorization for all other actions
        if not self.check_auth():
            return self.send_json(401, {"error": "Unauthorized: 必须先登录或提供节点认证令牌", "auth_required": True})

        # 3. Trigger rescan/sync
        if path == "/api/v1/sync":
            vms = scanner.scan_all_vms()
            nodes = scanner.get_cluster_nodes()
            return self.send_json(200, {
                "success": True,
                "message": "Cluster scan completed",
                "cluster_name": scanner.get_cluster_name(),
                "local_node": scanner.local_node_name,
                "local_ip": scanner.local_node_ip,
                "total_vms": len(vms),
                "nodes": nodes,
                "vms": vms,
                "pve_version": scanner.get_pve_version()
            })

        # 4. Modify Single VM GIC
        elif path.startswith("/api/v1/vms/") and path.endswith("/gic"):
            parts = path.split("/")
            if len(parts) >= 5 and parts[4].isdigit():
                vmid = int(parts[4])
                target_gic = body_data.get("gic_version")
                target_node = body_data.get("node")

                if not target_gic or target_gic not in ["2", "3", "host", "max", "default"]:
                    return self.send_json(400, {
                        "error": "Invalid gic_version. Allowed: '2', '3', 'host', 'max', 'default'"
                    })

                res = scanner.set_vm_gic_version(vmid, target_gic, node_name=target_node)
                status_code = 200 if res.get("success") else 500

                # Audit record
                user = self.get_current_user()
                target_desc = "系统默认(继承)" if target_gic == "host" else f"GICv{target_gic}"
                vm_name = (scanner.cached_vms.get(vmid) or {}).get("name") or f"VM {vmid}"
                st = "OK" if res.get("success") else "ERROR"
                detail = res.get("message") or res.get("error") or f"配置 VM {vmid} 为 {target_desc}"
                history_manager.add_record(
                    user=user,
                    source_node=scanner.local_node_name,
                    target_node=target_node or scanner.local_node_name,
                    vmid=vmid,
                    vm_name=vm_name,
                    action="gic",
                    action_desc=f"配置中断为 {target_desc}",
                    status=st,
                    detail=detail
                )
                return self.send_json(status_code, res)

        # 5. Batch Modify VM GIC
        elif path == "/api/v1/vms/batch-gic":
            vm_items = body_data.get("vms", [])
            target_gic = body_data.get("gic_version")

            if not target_gic or target_gic not in ["2", "3", "host", "max", "default"]:
                return self.send_json(400, {
                    "error": "Invalid gic_version. Allowed: '2', '3', 'host', 'max', 'default'"
                })

            if not vm_items:
                return self.send_json(400, {"error": "Empty vms list"})

            results = []
            for item in vm_items:
                vmid = item.get("vmid")
                node = item.get("node")
                if vmid:
                    r = scanner.set_vm_gic_version(vmid, target_gic, node_name=node)
                    results.append({"vmid": vmid, "result": r})

            scanner.scan_all_vms()
            user = self.get_current_user()
            target_desc = "系统默认(继承)" if target_gic == "host" else f"GICv{target_gic}"
            history_manager.add_record(
                user=user,
                source_node=scanner.local_node_name,
                target_node="集群多节点",
                vmid=None,
                vm_name=f"批量 {len(results)} 台",
                action="batch_gic",
                action_desc=f"批量配置中断为 {target_desc}",
                status="OK",
                detail=f"批量配置 {len(results)} 台虚拟机中断控制器为 {target_desc}"
            )
            return self.send_json(200, {
                "success": True,
                "batch_count": len(results),
                "results": results
            })

        # 6. Single VM Power Action (start, shutdown, reboot, stop)
        elif path.startswith("/api/v1/vms/") and path.endswith("/power"):
            parts = path.split("/")
            if len(parts) >= 5 and parts[4].isdigit():
                vmid = int(parts[4])
                action = body_data.get("action")
                target_node = body_data.get("node")

                if not action or action not in ["start", "shutdown", "reboot", "stop"]:
                    return self.send_json(400, {
                        "error": "Invalid power action. Allowed: 'start', 'shutdown', 'reboot', 'stop'"
                    })

                res = scanner.control_vm_power(vmid, action, node_name=target_node)
                status_code = 200 if res.get("success") else 500

                # Audit record
                user = self.get_current_user()
                action_names = {"start": "开机启动", "shutdown": "正常关机", "stop": "强制停止", "reboot": "系统重启"}
                action_desc = action_names.get(action, action)
                vm_name = (scanner.cached_vms.get(vmid) or {}).get("name") or f"VM {vmid}"
                st = "OK" if res.get("success") else "ERROR"
                detail = res.get("message") or res.get("error") or f"执行 VM {vmid} {action_desc}"
                history_manager.add_record(
                    user=user,
                    source_node=scanner.local_node_name,
                    target_node=target_node or scanner.local_node_name,
                    vmid=vmid,
                    vm_name=vm_name,
                    action=action,
                    action_desc=action_desc,
                    status=st,
                    detail=detail
                )
                return self.send_json(status_code, res)

        # 7. Batch VM Power Action
        elif path == "/api/v1/vms/batch-power":
            vm_items = body_data.get("vms", [])
            action = body_data.get("action")

            if not action or action not in ["start", "shutdown", "reboot", "stop"]:
                return self.send_json(400, {
                    "error": "Invalid power action. Allowed: 'start', 'shutdown', 'reboot', 'stop'"
                })

            if not vm_items:
                return self.send_json(400, {"error": "Empty vms list"})

            results = []
            for item in vm_items:
                vmid = item.get("vmid")
                node = item.get("node")
                if vmid:
                    r = scanner.control_vm_power(vmid, action, node_name=node)
                    results.append({"vmid": vmid, "result": r})

            scanner.scan_all_vms()
            user = self.get_current_user()
            action_names = {"start": "批量开机", "shutdown": "批量关机", "stop": "批量停止", "reboot": "批量重启"}
            action_desc = action_names.get(action, action)
            history_manager.add_record(
                user=user,
                source_node=scanner.local_node_name,
                target_node="集群多节点",
                vmid=None,
                vm_name=f"批量 {len(results)} 台",
                action=f"batch_{action}",
                action_desc=action_desc,
                status="OK",
                detail=f"批量对 {len(results)} 台虚拟机执行【{action_desc}】"
            )
            return self.send_json(200, {
                "success": True,
                "batch_count": len(results),
                "action": action,
                "results": results
            })

        # 8. Add Audit History Entry manually
        elif path == "/api/v1/history/add":
            user = self.get_current_user()
            entry = history_manager.add_record(
                user=body_data.get("user") or user,
                source_node=body_data.get("source_node") or scanner.local_node_name,
                target_node=body_data.get("target_node") or "-",
                vmid=body_data.get("vmid"),
                vm_name=body_data.get("vm_name"),
                action=body_data.get("action", "custom"),
                action_desc=body_data.get("action_desc", "操作"),
                status=body_data.get("status", "OK"),
                detail=body_data.get("detail", "")
            )
            return self.send_json(200, {"success": True, "entry": entry})

        # 9. Delete History Entry / Clear All (POST path)
        elif path == "/api/v1/history/delete":
            user = self.get_current_user()
            if not history_manager.is_root_user(user):
                return self.send_json(403, {
                    "success": False,
                    "error": "权限拒绝：仅 root@pam 超级管理员具备删除操作历史记录的权限！"
                })

            rec_id = body_data.get("id")
            if rec_id and rec_id != "all":
                ok, msg = history_manager.delete_record(rec_id, user)
            else:
                ok, msg = history_manager.clear_records(user)
            return self.send_json(200 if ok else 400, {
                "success": ok,
                "message": msg if ok else None,
                "error": None if ok else msg
            })

        self.send_json(404, {"error": f"Endpoint not found: {path}"})

    def do_DELETE(self):
        if not self.check_auth():
            return self.send_json(401, {"error": "Unauthorized", "auth_required": True})

        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path.rstrip('/')
        query_params = urllib.parse.parse_qs(parsed_url.query)

        # Delete History (DELETE /api/v1/history?id=xxx)
        if path == "/api/v1/history":
            user = self.get_current_user()
            if not history_manager.is_root_user(user):
                return self.send_json(403, {
                    "success": False,
                    "error": "权限拒绝：仅 root@pam 超级管理员具备删除操作历史记录的权限！"
                })

            rec_id = query_params.get("id", [None])[0]
            if rec_id and rec_id != "all":
                ok, msg = history_manager.delete_record(rec_id, user)
            else:
                ok, msg = history_manager.clear_records(user)
            return self.send_json(200 if ok else 400, {
                "success": ok,
                "message": msg if ok else None,
                "error": None if ok else msg
            })

        self.send_json(404, {"error": f"Endpoint not found: {path}"})

def run_api_server():
    ensure_cluster_token()
    server_address = (cfg.host, cfg.api_port)
    httpd = ThreadedHTTPServer(server_address, NodeAPIHandler)
    logger.info(f"PVE GIC Node API running on http://{cfg.host}:{cfg.api_port}")
    httpd.serve_forever()
