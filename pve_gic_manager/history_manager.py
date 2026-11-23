"""
Operation Audit History Manager for Proxmox VE ARM64 GIC Manager.
Persists all operations on disk and strictly enforces RBAC (only root can delete history).
"""
import os
import time
import json
import logging
import threading
from datetime import datetime

logger = logging.getLogger("pve_gic_history")

HISTORY_FILE = "/var/lib/pve-gic-manager/history.json"
MAX_HISTORY_ENTRIES = 1000

_history_lock = threading.Lock()

def _get_history_file():
    if os.name != 'nt' and os.path.exists('/var/lib/pve-gic-manager'):
        return HISTORY_FILE
    # Fallback directory
    base_dir = os.path.dirname(os.path.abspath(__file__))
    data_dir = os.path.join(base_dir, "data")
    os.makedirs(data_dir, exist_ok=True)
    return os.path.join(data_dir, "history.json")

def is_root_user(user):
    """
    Check if the user is a superadmin root user.
    Only root / root@pam is allowed to delete audit logs.
    """
    if not user:
        return False
    u = str(user).strip().lower()
    return u == "root" or u.startswith("root@")

def get_records(limit=200):
    """Retrieve audit history records sorted by newest first."""
    filepath = _get_history_file()
    with _history_lock:
        if not os.path.exists(filepath):
            return []
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, list):
                    return data[:limit]
        except Exception as e:
            logger.warning(f"Failed to read history from {filepath}: {e}")
            return []
    return []

def _save_records(records):
    filepath = _get_history_file()
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    if len(records) > MAX_HISTORY_ENTRIES:
        records = records[:MAX_HISTORY_ENTRIES]
    try:
        temp_file = filepath + ".tmp"
        with open(temp_file, "w", encoding="utf-8") as f:
            json.dump(records, f, ensure_ascii=False, indent=2)
        os.replace(temp_file, filepath)
        return True
    except Exception as e:
        logger.error(f"Failed to save history to {filepath}: {e}")
        return False

def add_record(user, source_node, target_node, vmid, vm_name, action, action_desc, status, detail):
    """
    Append an operation audit entry to permanent disk storage.
    """
    filepath = _get_history_file()
    now = datetime.now()
    entry = {
        "id": f"hist_{int(time.time()*1000)}_{int(time.time()*1000) % 1000}",
        "timestamp": time.time(),
        "time": now.strftime("%Y-%m-%d %H:%M:%S"),
        "user": user or "root@pam",
        "source_node": source_node or "pve",
        "target_node": target_node or "-",
        "vmid": vmid,
        "vm_name": vm_name or (f"VM {vmid}" if vmid else ""),
        "action": action,
        "action_desc": action_desc,
        "status": status, # "OK" | "WARN" | "ERROR" | "IN_PROGRESS"
        "detail": detail
    }
    with _history_lock:
        records = []
        if os.path.exists(filepath):
            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    records = json.load(f)
            except Exception:
                records = []
        records.insert(0, entry)
        _save_records(records)
    logger.info(f"Audit log: [{entry['user']}] {entry['source_node']} -> {entry['target_node']} VM {vmid}: {action_desc} ({status})")
    return entry

def delete_record(record_id, user):
    """
    Delete a single audit entry. Strictly restricted to root.
    """
    if not is_root_user(user):
        return False, "权限拒绝：仅 root 超级管理员具备删除操作历史记录的权限！"
    filepath = _get_history_file()
    with _history_lock:
        records = []
        if os.path.exists(filepath):
            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    records = json.load(f)
            except Exception:
                records = []
        new_records = [r for r in records if r.get("id") != record_id]
        if len(new_records) == len(records):
            return False, f"未找到指定 ID 的历史记录: {record_id}"
        _save_records(new_records)
    return True, "历史记录已成功删除"

def clear_records(user):
    """
    Clear all audit entries. Strictly restricted to root.
    """
    if not is_root_user(user):
        return False, "权限拒绝：仅 root 超级管理员具备清空操作历史记录的权限！"
    with _history_lock:
        _save_records([])
    return True, "全部操作历史记录已成功清空"
