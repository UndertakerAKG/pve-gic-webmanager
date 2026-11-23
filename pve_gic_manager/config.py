"""
Proxmox VE ARM64 GIC Web & API Manager
Configuration Module
"""
import os
import json
import socket
import logging

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] [%(name)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger("pve_gic_config")

DEFAULT_CONFIG_PATH = "/etc/pve-gic-manager/config.json"
CLUSTER_TOKEN_FILE = "/etc/pve/pve-gic-token"
LOCAL_TOKEN_FILE = "/etc/pve-gic-manager/auth.token"

DEFAULT_CONFIG = {
    "host": "0.0.0.0",
    "api_port": 8004,
    "web_port": 8005,
    "sync_interval_seconds": 5,
    "pve_cluster_dir": "/etc/pve",
    "pve_nodes_dir": "/etc/pve/nodes",
    "qemu_run_dir": "/var/run/qemu-server",
    "cluster_shared_secret": "",
    "log_level": "INFO"
}

class Config:
    def __init__(self, config_file=DEFAULT_CONFIG_PATH):
        self.config_file = config_file
        self.data = dict(DEFAULT_CONFIG)
        self.load()

    def load(self):
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, "r", encoding="utf-8") as f:
                    user_cfg = json.load(f)
                    self.data.update(user_cfg)
                    logger.info(f"Loaded configuration from {self.config_file}")
            except Exception as e:
                logger.warning(f"Failed to load config {self.config_file}: {e}, using defaults")

    def save(self):
        try:
            os.makedirs(os.path.dirname(self.config_file), exist_ok=True)
            with open(self.config_file, "w", encoding="utf-8") as f:
                json.dump(self.data, f, indent=4)
        except Exception as e:
            logger.error(f"Failed to save config to {self.config_file}: {e}")

    @property
    def host(self):
        return self.data.get("host", "0.0.0.0")

    @property
    def api_port(self):
        return int(self.data.get("api_port", 8004))

    @property
    def web_port(self):
        return int(self.data.get("web_port", 8005))

    @property
    def sync_interval(self):
        return int(self.data.get("sync_interval_seconds", 5))

    @property
    def pve_nodes_dir(self):
        return self.data.get("pve_nodes_dir", "/etc/pve/nodes")

    @property
    def qemu_run_dir(self):
        return self.data.get("qemu_run_dir", "/var/run/qemu-server")

    @property
    def cluster_token(self):
        # 1. Check if token in memory/config
        token = self.data.get("cluster_shared_secret")
        if token and len(token) >= 16:
            return token.strip()

        # 2. Check cluster-wide shared token file (/etc/pve/pve-gic-token)
        if os.path.exists(CLUSTER_TOKEN_FILE):
            try:
                with open(CLUSTER_TOKEN_FILE, "r", encoding="utf-8") as f:
                    t = f.read().strip()
                    if t:
                        return t
            except Exception:
                pass

        # 3. Check local token file
        if os.path.exists(LOCAL_TOKEN_FILE):
            try:
                with open(LOCAL_TOKEN_FILE, "r", encoding="utf-8") as f:
                    t = f.read().strip()
                    if t:
                        return t
            except Exception:
                pass

        return ""

    def set_cluster_token(self, token):
        self.data["cluster_shared_secret"] = token
        # Try persisting to cluster storage or local storage
        saved = False
        if os.path.exists("/etc/pve"):
            try:
                with open(CLUSTER_TOKEN_FILE, "w", encoding="utf-8") as f:
                    f.write(token + "\n")
                os.chmod(CLUSTER_TOKEN_FILE, 0o600)
                saved = True
            except Exception:
                pass

        if not saved:
            try:
                os.makedirs(os.path.dirname(LOCAL_TOKEN_FILE), exist_ok=True)
                with open(LOCAL_TOKEN_FILE, "w", encoding="utf-8") as f:
                    f.write(token + "\n")
                os.chmod(LOCAL_TOKEN_FILE, 0o600)
            except Exception:
                pass

cfg = Config()
