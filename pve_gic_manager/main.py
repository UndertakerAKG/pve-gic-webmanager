"""
Main Entry Point for Proxmox VE ARM64 GIC Management Service
Starts dual servers: API (8004) and Web UI (8005) with cluster background sync.
"""
import sys
import os
import time
import signal
import threading
import logging
from .config import cfg
from .pve_scanner import scanner
from .cluster_auth import ensure_cluster_token
from .api_service import run_api_server
from .web_service import run_web_server

logging.basicConfig(
    level=getattr(logging, cfg.data.get("log_level", "INFO")),
    format='%(asctime)s [%(levelname)s] [%(name)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger("pve_gic_main")

def main():
    logger.info("=======================================================")
    logger.info(" Starting Proxmox VE ARM64 GIC Management System v1.0.0 ")
    logger.info("=======================================================")

    # 1. Ensure token exists
    token = ensure_cluster_token()
    logger.info(f"Local Node: {scanner.local_node_name} (IP: {scanner.local_node_ip})")
    logger.info(f"Cluster Token initialized (length: {len(token)})")

    # 2. Initial scan
    logger.info("Performing initial VM and cluster discovery...")
    vms = scanner.scan_all_vms()
    nodes = scanner.get_cluster_nodes()
    logger.info(f"Discovered {len(nodes)} node(s), {len(vms)} VM(s)")

    # 3. Start background watcher (Requirement 8)
    scanner.start_background_watcher()

    # 4. Launch API Server (Port 8004) in background thread
    api_thread = threading.Thread(target=run_api_server, daemon=True, name="api_8004")
    api_thread.start()

    # 5. Launch Web Server (Port 8005) in background thread
    web_thread = threading.Thread(target=run_web_server, daemon=True, name="web_8005")
    web_thread.start()

    logger.info(f"Web UI: http://{scanner.local_node_ip}:{cfg.web_port}")
    logger.info(f"Node API: http://{scanner.local_node_ip}:{cfg.api_port}")
    logger.info("Services are running. Press Ctrl+C to stop.")

    # Graceful shutdown handling
    stop_event = threading.Event()

    def signal_handler(signum, frame):
        logger.info("Shutdown signal received. Stopping services...")
        scanner.watcher_running = False
        stop_event.set()
        sys.exit(0)

    try:
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
    except Exception:
        pass

    while not stop_event.is_set():
        time.sleep(1)

if __name__ == "__main__":
    main()
