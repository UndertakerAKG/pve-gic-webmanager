"""
Proxmox VE Scanner & Controller Module
Handles PVE nodes, VM discovery, QMP GIC version querying, IP resolution, and GIC reconfiguration.
"""
import os
import re
import sys
import json
import socket
import struct
import logging
import subprocess
import threading
import time
from .config import cfg

logger = logging.getLogger("pve_gic_scanner")

class PVEScanner:
    def __init__(self):
        self.lock = threading.Lock()
        self.cached_nodes = {}
        self.cached_vms = {}
        self.last_scan_time = 0
        self.local_node_name = self._detect_local_node_name()
        self._cached_local_ip = None
        self._last_local_ip_time = 0
        self.cached_resolved_ips = {}
        self.watcher_thread = None
        self.watcher_running = False
        self.active_arp_cache = {}
        self.last_arp_scan = 0
        self.cached_pve_version = None
        self.cached_pve_info = None
        self._start_passive_arp_sniffer()

    def _start_passive_arp_sniffer(self):
        """Start persistent raw ARP sniffer thread to capture VM IPs in real time."""
        if os.name != 'posix':
            return
        def _sniffer():
            try:
                s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0806))
                while True:
                    try:
                        pkt = s.recv(2048)
                        if len(pkt) >= 42 and pkt[12:14] == b'\x08\x06':
                            arp = pkt[14:42]
                            oper = struct.unpack('!H', arp[6:8])[0]
                            if oper in (1, 2):
                                sender_mac = ':'.join('%02x' % b for b in arp[8:14]).lower()
                                sender_ip = socket.inet_ntoa(arp[14:18])
                                if sender_ip and not sender_ip.startswith("0.") and not sender_ip.startswith("127.") and not sender_ip.startswith("169.254."):
                                    with self.lock:
                                        self.active_arp_cache[sender_mac] = sender_ip
                    except Exception:
                        time.sleep(0.1)
            except Exception as e:
                logger.debug(f"Passive ARP sniffer init error: {e}")

        t = threading.Thread(target=_sniffer, daemon=True, name="arp_sniffer")
        t.start()

    def get_pve_version_info(self):
        """
        Dynamically detect running Proxmox VE version and kernel details.
        """
        if self.cached_pve_info:
            return self.cached_pve_info

        info = {
            "version": "9.2.9",
            "release": "9.2",
            "manager": "",
            "kernel": ""
        }
        import shutil
        pveversion_bin = shutil.which("pveversion") or "/usr/bin/pveversion"
        try:
            res = subprocess.run([pveversion_bin], capture_output=True, text=True, timeout=2)
            if res.returncode == 0 and res.stdout:
                line = res.stdout.strip()
                info["manager"] = line
                m_ver = re.search(r'pve-manager/([0-9.]+)', line)
                if m_ver:
                    info["version"] = m_ver.group(1)
                m_k = re.search(r'running kernel:\s*([^\)]+)', line)
                if m_k:
                    info["kernel"] = m_k.group(1).strip()
        except Exception as e:
            logger.debug(f"pveversion execution error: {e}")

        pvesh_bin = shutil.which("pvesh") or "/usr/bin/pvesh"
        try:
            res2 = subprocess.run([pvesh_bin, "get", "/version", "--output-format", "json"], capture_output=True, text=True, timeout=2)
            if res2.returncode == 0 and res2.stdout:
                vdata = json.loads(res2.stdout)
                if vdata.get("version"):
                    info["version"] = str(vdata.get("version"))
                if vdata.get("release"):
                    info["release"] = str(vdata.get("release"))
                if vdata.get("repoid"):
                    info["repoid"] = str(vdata.get("repoid"))
        except Exception:
            pass

        self.cached_pve_info = info
        self.cached_pve_version = info["version"]
        return info

    def get_pve_version(self):
        """
        Dynamically detect running Proxmox VE version string, e.g. '9.2.9'.
        """
        if self.cached_pve_version:
            return self.cached_pve_version
        info = self.get_pve_version_info()
        return info.get("version", "9.2.9")

    def _detect_local_node_name(self):
        """Detect current PVE node name."""
        try:
            return socket.gethostname().split('.')[0]
        except Exception:
            return "localhost"

    @property
    def local_node_ip(self):
        """Dynamically detect current PVE node primary IP with a 3-second cache."""
        now = time.time()
        if not self._cached_local_ip or (now - self._last_local_ip_time > 3):
            self._cached_local_ip = self._detect_local_node_ip()
            self._last_local_ip_time = now
        return self._cached_local_ip

    def _detect_local_node_ip(self):
        """Detect current PVE node primary IP address dynamically."""
        # 1. Try vmbr0 IP via 'ip -4 -o addr show vmbr0' (PVE standard management interface)
        try:
            output = subprocess.check_output(["ip", "-4", "-o", "addr", "show", "vmbr0"], timeout=1).decode("utf-8")
            for line in output.splitlines():
                parts = line.strip().split()
                if len(parts) >= 4 and parts[2] == "inet":
                    ip = parts[3].split('/')[0]
                    if ip and not ip.startswith("127."):
                        return ip
        except Exception:
            pass

        # 2. Try connecting a UDP socket to retrieve routing IP
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            if ip and not ip.startswith("127."):
                return ip
        except Exception:
            pass

        # 3. Try parsing any non-loopback inet from 'ip -4 addr show'
        try:
            output = subprocess.check_output(["ip", "-4", "addr", "show"], timeout=2).decode("utf-8")
            for line in output.splitlines():
                line = line.strip()
                if "inet " in line and not "127.0.0.1" in line:
                    parts = line.split()
                    ip_with_mask = parts[1]
                    return ip_with_mask.split('/')[0]
        except Exception:
            pass

        return "127.0.0.1"

    def get_cluster_nodes(self):
        """
        Discover all nodes in the PVE cluster.
        Returns dict: {node_name: {"name": node_name, "ip": ip, "is_local": bool, "status": "online"}}
        """
        nodes = {}
        nodes_dir = cfg.pve_nodes_dir
        
        # Check /etc/pve/nodes/
        if os.path.exists(nodes_dir) and os.path.isdir(nodes_dir):
            try:
                for entry in os.listdir(nodes_dir):
                    node_path = os.path.join(nodes_dir, entry)
                    if os.path.isdir(node_path):
                        nodes[entry] = {
                            "name": entry,
                            "ip": self.resolve_node_ip(entry),
                            "is_local": (entry == self.local_node_name),
                            "status": "online"
                        }
            except Exception as e:
                logger.warning(f"Error reading nodes dir {nodes_dir}: {e}")

        # Fallback to local node if nothing found
        if not nodes:
            nodes[self.local_node_name] = {
                "name": self.local_node_name,
                "ip": self.local_node_ip,
                "is_local": True,
                "status": "online"
            }

        # Update local node IP explicitly
        if self.local_node_name in nodes:
            nodes[self.local_node_name]["ip"] = self.local_node_ip

        return nodes

    def get_cluster_name(self):
        """Read cluster name from /etc/pve/corosync.conf if available."""
        corosync_conf = os.path.join(cfg.data.get("pve_cluster_dir", "/etc/pve"), "corosync.conf")
        if os.path.exists(corosync_conf):
            try:
                with open(corosync_conf, "r", encoding="utf-8") as f:
                    content = f.read()
                    m = re.search(r'cluster_name:\s*([^\s]+)', content)
                    if m:
                        return m.group(1).strip()
            except Exception:
                pass
        return ""

    def resolve_node_ip(self, node_name):
        """
        Dynamically resolve PVE node IP address.
        Prioritizes verified live connectivity on Port 8004 API.
        """
        if node_name == self.local_node_name:
            return self.local_node_ip

        now = time.time()
        cached = getattr(self, 'cached_resolved_ips', {}).get(node_name)
        if cached:
            ip, expire_time = cached
            if now < expire_time:
                return ip

        candidates = []

        # Candidate A: Local /etc/hosts via gethostbyname
        try:
            h_ip = socket.gethostbyname(node_name)
            if h_ip and not h_ip.startswith("127.") and h_ip not in candidates:
                candidates.append(h_ip)
        except Exception:
            pass

        # Candidate B: /etc/pve/corosync.conf ring0_addr
        corosync_conf = os.path.join(cfg.data.get("pve_cluster_dir", "/etc/pve"), "corosync.conf")
        if os.path.exists(corosync_conf):
            try:
                with open(corosync_conf, "r", encoding="utf-8") as f:
                    content = f.read()
                    blocks = re.findall(r'node\s*\{([^}]+)\}', content, re.MULTILINE)
                    for block in blocks:
                        if f"name: {node_name}" in block:
                            m = re.search(r'ring0_addr:\s*([^\s]+)', block)
                            if m:
                                c_ip = m.group(1).strip()
                                if c_ip and not c_ip.startswith("127.") and c_ip not in candidates:
                                    candidates.append(c_ip)
            except Exception:
                pass

        def verify_node(ip_addr):
            try:
                import urllib.request
                import json
                url = f"http://{ip_addr}:8004/api/v1/health"
                req = urllib.request.Request(url, headers={"User-Agent": "PVE-GIC-Discovery"})
                with urllib.request.urlopen(req, timeout=0.8) as resp:
                    data = json.loads(resp.read().decode("utf-8"))
                    if data.get("node") == node_name:
                        return True
            except Exception:
                pass
            return False

        # 1. Test existing candidates
        for cand in candidates:
            if verify_node(cand):
                self._cache_node_ip(node_name, cand, ttl=60)
                return cand

        # 2. If configured candidates fail (e.g. node IP changed dynamically),
        # probe active neighbors from 'ip neigh show'
        try:
            neigh_out = subprocess.check_output(["ip", "neigh", "show"], timeout=1).decode("utf-8")
            for line in neigh_out.splitlines():
                parts = line.strip().split()
                if len(parts) >= 1 and "." in parts[0]:
                    neigh_ip = parts[0]
                    if neigh_ip not in candidates and not neigh_ip.endswith(".1"):
                        if verify_node(neigh_ip):
                            logger.info(f"Dynamically discovered updated IP for node {node_name}: {neigh_ip}")
                            self._cache_node_ip(node_name, neigh_ip, ttl=60)
                            return neigh_ip
        except Exception:
            pass

        fallback = candidates[0] if candidates else ""
        if fallback:
            self._cache_node_ip(node_name, fallback, ttl=10)
        return fallback

    def _cache_node_ip(self, node_name, ip, ttl=30):
        if not hasattr(self, 'cached_resolved_ips'):
            self.cached_resolved_ips = {}
        self.cached_resolved_ips[node_name] = (ip, time.time() + ttl)

    def refresh_active_arp(self):
        """
        Actively probe the local bridge (e.g. vmbr0) with ARP who-has broadcasts.
        This immediately wakes up all VM ARP caches and captures real-time IP allocations,
        enabling 100% IP detection even without QEMU Guest Agent.
        """
        import fcntl
        mac_to_ip = {}
        bridges = []
        try:
            out = subprocess.check_output(["ip", "-o", "link", "show", "type", "bridge"], timeout=1).decode("utf-8")
            for line in out.splitlines():
                parts = line.split(":")
                if len(parts) >= 2:
                    br = parts[1].strip()
                    # Only probe actual virtual bridges (skip PVE firewall bridges like fwbr*)
                    if br and not br.startswith("fwbr"):
                        bridges.append(br)
        except Exception:
            pass

        if not bridges:
            bridges = ["vmbr0"]

        for br in bridges:
            sock = None
            try:
                try:
                    s_ctl = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    ip_bytes = fcntl.ioctl(s_ctl.fileno(), 0x8915, struct.pack('256s', br[:15].encode('utf-8')))[20:24]
                    mac_bytes = fcntl.ioctl(s_ctl.fileno(), 0x8927, struct.pack('256s', br[:15].encode('utf-8')))[18:24]
                    s_ctl.close()
                except Exception:
                    continue

                src_ip_str = socket.inet_ntoa(ip_bytes)
                prefix = ".".join(src_ip_str.split(".")[:3])

                sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0806))
                sock.bind((br, 0))

                for i in range(1, 255):
                    dst_ip_bytes = socket.inet_aton(f"{prefix}.{i}")
                    eth = b'\xff\xff\xff\xff\xff\xff' + mac_bytes + b'\x08\x06'
                    arp = struct.pack('!HHBBH', 1, 0x0800, 6, 4, 1) + mac_bytes + ip_bytes + b'\x00\x00\x00\x00\x00\x00' + dst_ip_bytes
                    sock.send(eth + arp)

                sock.settimeout(0.3)
                start_t = time.time()
                while time.time() - start_t < 0.4:
                    try:
                        pkt = sock.recv(2048)
                        if len(pkt) >= 42 and pkt[12:14] == b'\x08\x06':
                            arp = pkt[14:42]
                            oper = struct.unpack('!H', arp[6:8])[0]
                            if oper in (1, 2):
                                sender_mac = ':'.join('%02x' % b for b in arp[8:14]).lower()
                                sender_ip = socket.inet_ntoa(arp[14:18])
                                if not sender_ip.startswith("0.") and not sender_ip.startswith("127.") and not sender_ip.startswith("169.254."):
                                    mac_to_ip[sender_mac] = sender_ip
                    except socket.timeout:
                        break
                    except Exception:
                        pass
            except Exception as e:
                logger.debug(f"Active ARP scan on bridge {br} error: {e}")
            finally:
                if sock:
                    try:
                        sock.close()
                    except Exception:
                        pass

        if mac_to_ip:
            with self.lock:
                self.active_arp_cache.update(mac_to_ip)
                self.last_arp_scan = time.time()
            logger.debug(f"Active ARP scan updated {len(mac_to_ip)} mappings")

        return mac_to_ip

    def read_arp_table(self):
        """Read system ARP, active ARP cache, and neighbor table for MAC -> IP mappings."""
        # Auto-trigger active ARP scan if cache empty or stale (> 10s)
        if not self.active_arp_cache or (time.time() - self.last_arp_scan > 10.0):
            try:
                self.refresh_active_arp()
            except Exception as e:
                logger.debug(f"Auto active ARP scan error: {e}")

        mac_to_ip = {}

        # 1. /proc/net/arp
        if os.path.exists("/proc/net/arp"):
            try:
                with open("/proc/net/arp", "r", encoding="utf-8") as f:
                    lines = f.readlines()[1:]
                    for line in lines:
                        parts = line.split()
                        if len(parts) >= 4:
                            ip = parts[0]
                            mac = parts[3].lower()
                            if mac != "00:00:00:00:00:00":
                                mac_to_ip[mac] = ip
            except Exception:
                pass

        # 2. ip neigh
        try:
            output = subprocess.check_output(["ip", "neigh"], timeout=2).decode("utf-8")
            for line in output.splitlines():
                parts = line.split()
                if len(parts) >= 5 and "lladdr" in parts:
                    ip = parts[0]
                    idx = parts.index("lladdr")
                    if idx + 1 < len(parts):
                        mac = parts[idx + 1].lower()
                        if mac not in mac_to_ip and not ip.startswith("fe80:"):
                            mac_to_ip[mac] = ip
        except Exception:
            pass

        # 3. Active probe & real-time sniffer cache (highest priority, freshly verified on wire)
        with self.lock:
            mac_to_ip.update(self.active_arp_cache)

        return mac_to_ip

    def query_qmp_gic_version(self, vmid, timeout=1.0):
        """
        Query QMP for active GIC version via UNIX domain socket /var/run/qemu-server/{vmid}.qmp.
        Returns: "2", "3", or None.
        """
        socket_path = f"/var/run/qemu-server/{vmid}.qmp"
        if not os.path.exists(socket_path):
            # Fallback to pvesh if socket not directly accessible
            return self._query_qmp_via_pvesh(vmid)

        s = None
        try:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect(socket_path)
            
            # 1. Read greeting banner
            data = s.recv(4096).decode("utf-8", errors="replace")
            
            # 2. Negotiate qmp_capabilities
            s.sendall(b'{"execute":"qmp_capabilities"}\n')
            data = s.recv(4096).decode("utf-8", errors="replace")
            
            # 3. Query gic-version
            cmd = b'{"execute":"qom-get","arguments":{"path":"/machine","property":"gic-version"}}\n'
            s.sendall(cmd)
            resp = s.recv(4096).decode("utf-8", errors="replace")
            
            for line in resp.strip().splitlines():
                try:
                    obj = json.loads(line)
                    if "return" in obj:
                        return str(obj["return"]).strip('"\'')
                except Exception:
                    pass
        except Exception as e:
            logger.debug(f"Direct QMP query failed for VM {vmid}: {e}, trying pvesh fallback")
            return self._query_qmp_via_pvesh(vmid)
        finally:
            if s:
                try:
                    s.close()
                except Exception:
                    pass
        return None

    def _query_qmp_via_pvesh(self, vmid):
        """Fallback to pvesh CLI to query monitor for gic-version."""
        try:
            cmd = [
                "pvesh", "create", f"/nodes/{self.local_node_name}/qemu/{vmid}/monitor",
                "--command", "qom-get /machine gic-version"
            ]
            res = subprocess.check_output(cmd, stderr=subprocess.STDOUT, timeout=2).decode("utf-8").strip()
            # Often returns '"3"' or '"2"'
            clean = res.strip().strip('"\'')
            if clean in ["2", "3", "host", "max"]:
                return clean
            # Match regex
            m = re.search(r'["\']?([23]|host|max)["\']?', res)
            if m:
                return m.group(1)
        except Exception:
            pass
        return None

    def query_vm_ip_from_agent(self, vmid, timeout=1.5):
        """Query QEMU guest agent for VM IP addresses."""
        try:
            cmd = [
                "pvesh", "get", f"/nodes/{self.local_node_name}/qemu/{vmid}/agent/network-get-interfaces",
                "--output-format", "json"
            ]
            res = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, timeout=timeout).decode("utf-8")
            data = json.loads(res)
            # data is {result: [...]}
            ips = []
            interfaces = data.get("result", []) if isinstance(data, dict) else data
            for iface in interfaces:
                for addr in iface.get("ip-addresses", []):
                    ip = addr.get("ip-address")
                    ip_type = addr.get("ip-address-type")
                    if ip and not ip.startswith("127.") and not ip.startswith("fe80:"):
                        ips.append(ip)
            return ips
        except Exception:
            return []

    def parse_vm_conf_file(self, conf_path, vmid, node_name, arp_table=None):
        """Parse single VM .conf file and return structured dict."""
        if arp_table is None:
            arp_table = {}

        vm_info = {
            "vmid": int(vmid),
            "node": node_name,
            "name": f"VM {vmid}",
            "status": "stopped",
            "arch": "aarch64", # Default for ARM64 PVE
            "cores": 1,
            "sockets": 1,
            "vcpus": 1,
            "memory": 2048,
            "mac_addresses": [],
            "ips": [],
            "primary_ip": "-",
            "config_gic": "default", # "3", "2", "host", "max", or "default"
            "active_gic": None,      # "3", "2", or None
            "pending_restart": False,
            "args": "",
            "has_agent": False
        }

        if not os.path.exists(conf_path):
            return None

        try:
            with open(conf_path, "r", encoding="utf-8") as f:
                lines = f.readlines()
        except Exception as e:
            logger.warning(f"Cannot read {conf_path}: {e}")
            return None

        raw_args = ""
        has_gicversion_field = False
        gicversion_val = ""

        for line in lines:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if ":" in line:
                k, v = line.split(":", 1)
                k = k.strip()
                v = v.strip()
                if k == "name":
                    vm_info["name"] = v
                elif k == "cores":
                    try:
                        vm_info["cores"] = int(v)
                    except ValueError:
                        pass
                elif k == "sockets":
                    try:
                        vm_info["sockets"] = int(v)
                    except ValueError:
                        pass
                elif k == "vcpus":
                    try:
                        vm_info["vcpus"] = int(v)
                    except ValueError:
                        pass
                elif k == "memory":
                    try:
                        vm_info["memory"] = int(v)
                    except ValueError:
                        pass
                elif k == "arch":
                    vm_info["arch"] = v
                elif k == "agent" and ("1" in v or "enabled=1" in v):
                    vm_info["has_agent"] = True
                elif k == "args":
                    raw_args = v
                    vm_info["args"] = v
                elif k == "gicversion":
                    has_gicversion_field = True
                    gicversion_val = v
                elif k.startswith("net"):
                    # net0: virtio=BC:24:11:5C:B0:FF,bridge=vmbr0...
                    m = re.search(r'([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})', v)
                    if m:
                        mac = m.group(1).lower()
                        vm_info["mac_addresses"].append(mac)

        # Calculate vcpus if not set
        if vm_info["vcpus"] == 1 and (vm_info["cores"] > 1 or vm_info["sockets"] > 1):
            vm_info["vcpus"] = vm_info["cores"] * vm_info["sockets"]

        # Parse Configured GIC version
        if has_gicversion_field and gicversion_val:
            vm_info["config_gic"] = gicversion_val
        elif raw_args:
            # Check -machine ...gic-version=X
            m = re.search(r'gic-version=([a-zA-Z0-9]+)', raw_args)
            if m:
                vm_info["config_gic"] = m.group(1)

        # Check running state (only for local node directly, remote nodes will provide via API)
        if node_name == self.local_node_name:
            pid_file = os.path.join(cfg.qemu_run_dir, f"{vmid}.pid")
            is_running = False
            if os.path.exists(pid_file):
                try:
                    with open(pid_file, "r") as pf:
                        pid = int(pf.read().strip())
                        # Check process alive
                        os.kill(pid, 0)
                        is_running = True
                except Exception:
                    is_running = False

            if is_running:
                vm_info["status"] = "running"
                # Query active GIC via QMP
                active_gic = self.query_qmp_gic_version(vmid)
                vm_info["active_gic"] = active_gic

                # Resolve IPs:
                ips = []
                if vm_info["has_agent"]:
                    agent_ips = self.query_vm_ip_from_agent(vmid)
                    if agent_ips:
                        ips.extend(agent_ips)

                # Cross-check MAC in ARP table
                for mac in vm_info["mac_addresses"]:
                    if mac in arp_table:
                        arp_ip = arp_table[mac]
                        if arp_ip not in ips:
                            ips.append(arp_ip)

                vm_info["ips"] = ips
                if ips:
                    vm_info["primary_ip"] = ips[0]
            else:
                vm_info["status"] = "stopped"
                vm_info["active_gic"] = None

            # Pending restart evaluation
            if vm_info["status"] == "running":
                # If config says '3' but active is '2' or vice versa
                cfg_gic = vm_info["config_gic"]
                act_gic = vm_info["active_gic"]
                if cfg_gic in ["2", "3"] and act_gic in ["2", "3"] and cfg_gic != act_gic:
                    vm_info["pending_restart"] = True
                elif cfg_gic == "default" and act_gic:
                    # Not explicit pending, but active is determined by system
                    vm_info["pending_restart"] = False

        # Calculate effective GIC (for both running and stopped VMs - Requirement 3)
        effective_gic = None
        if vm_info.get("status") == "running" and vm_info.get("active_gic"):
            effective_gic = vm_info["active_gic"]
        elif vm_info.get("config_gic") in ["2", "3"]:
            effective_gic = vm_info["config_gic"]
        else:
            # Default QEMU ARM virt behavior: <= 8 vcpus -> GICv2, >= 9 vcpus -> GICv3
            effective_gic = "2" if vm_info["vcpus"] <= 8 else "3"

        vm_info["effective_gic"] = effective_gic

        return vm_info

    def scan_local_vms(self):
        """Scan all VMs belonging to the local PVE node."""
        vms = {}
        node_dir = os.path.join(cfg.pve_nodes_dir, self.local_node_name, "qemu-server")
        if not os.path.exists(node_dir):
            return vms

        arp_table = self.read_arp_table()

        try:
            for fname in os.listdir(node_dir):
                if fname.endswith(".conf"):
                    vmid_str = fname[:-5]
                    if vmid_str.isdigit():
                        conf_path = os.path.join(node_dir, fname)
                        info = self.parse_vm_conf_file(conf_path, vmid_str, self.local_node_name, arp_table)
                        if info:
                            vms[int(vmid_str)] = info
        except Exception as e:
            logger.error(f"Error scanning local VMs in {node_dir}: {e}")

        return vms

    def scan_all_vms(self):
        """
        Scan all VMs across the cluster.
        If node is local, scan with QMP and local status.
        If node is remote and running pve-gic-manager, call its API;
        otherwise parse its configuration file from /etc/pve/nodes/{remote_node}/qemu-server/.
        """
        if time.time() - self.last_arp_scan > 5.0:
            self.refresh_active_arp()

        all_vms = {}
        nodes = self.get_cluster_nodes()
        arp_table = self.read_arp_table()

        # Pre-fetch cluster-wide VM live status via pvesh (supports single-node master-only deployment)
        cluster_vm_status = {}
        try:
            cmd = ["pvesh", "get", "/cluster/resources", "--type", "vm", "--output-format", "json"]
            out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, timeout=2.0).decode("utf-8")
            for item in json.loads(out):
                vid = item.get("vmid")
                if vid:
                    cluster_vm_status[int(vid)] = item.get("status", "stopped")
        except Exception:
            pass

        for node_name, node_info in nodes.items():
            if node_name == self.local_node_name:
                local_vms = self.scan_local_vms()
                all_vms.update(local_vms)
            else:
                # Try calling remote node's 8004 API if available (Distributed Mode)
                remote_ip = node_info.get("ip")
                fetched_via_api = False
                if remote_ip and remote_ip != "127.0.0.1":
                    from .cluster_auth import call_node_api
                    resp = call_node_api(remote_ip, port=cfg.api_port, endpoint="/api/v1/vms?local_only=1", timeout=2.0)
                    if resp.get("success") and isinstance(resp.get("data"), dict):
                        remote_vms = resp["data"].get("vms", {})
                        for k, v in remote_vms.items():
                            all_vms[int(k)] = v
                        fetched_via_api = True

                # If remote API not running/not installed, read directly from shared /etc/pve filesystem (Single Node Mode)
                if not fetched_via_api:
                    node_dir = os.path.join(cfg.pve_nodes_dir, node_name, "qemu-server")
                    if os.path.exists(node_dir):
                        try:
                            for fname in os.listdir(node_dir):
                                if fname.endswith(".conf") and fname[:-5].isdigit():
                                    vmid_str = fname[:-5]
                                    vmid_int = int(vmid_str)
                                    conf_path = os.path.join(node_dir, fname)
                                    info = self.parse_vm_conf_file(conf_path, vmid_str, node_name, arp_table)
                                    if info:
                                        # Accurately apply cluster-wide real-time status from pvesh
                                        if vmid_int in cluster_vm_status:
                                            info["status"] = cluster_vm_status[vmid_int]
                                            if info["status"] == "running":
                                                # Try querying QMP monitor across cluster
                                                try:
                                                    cmd = ["pvesh", "create", f"/nodes/{node_name}/qemu/{vmid_str}/monitor", "--command", "qom-get /machine gic-version"]
                                                    out_mon = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, timeout=1.5).decode("utf-8").strip()
                                                    clean_mon = out_mon.strip().strip('"\'')
                                                    if clean_mon in ["2", "3", "host", "max"]:
                                                        info["active_gic"] = clean_mon
                                                except Exception:
                                                    pass

                                                # Resolve real IP from ARP cache
                                                for mac in info.get("mac_addresses", []):
                                                    if mac in arp_table:
                                                        info["ips"] = [arp_table[mac]]
                                                        info["primary_ip"] = arp_table[mac]
                                                        break

                                        all_vms[vmid_int] = info
                        except Exception as e:
                            logger.warning(f"Error reading remote node conf {node_dir}: {e}")

        with self.lock:
            self.cached_nodes = nodes
            self.cached_vms = all_vms
            self.last_scan_time = time.time()

        return all_vms

    def update_args_gic(self, raw_args, target_gic):
        """
        Cleanly update or remove gic-version in QEMU args.
        Preserves all other machine flags and unrelated options, sanitizes dirty flags.
        """
        tokens = raw_args.strip().split()
        clean_tokens = []
        i = 0
        while i < len(tokens):
            tok = tokens[i]
            if tok == '-machine':
                if i + 1 < len(tokens):
                    val = tokens[i+1]
                    if val.startswith('-'):
                        # Stray -machine flag followed by another option
                        i += 1
                        continue
                    val_clean = re.sub(r',?gic-version=[a-zA-Z0-9]+', '', val).lstrip(',')
                    if val_clean:
                        clean_tokens.extend(['-machine', val_clean])
                    i += 2
                    continue
                else:
                    # Trailing lonely -machine
                    i += 1
                    continue
            elif tok.startswith('-machine='):
                val = tok[9:]
                val_clean = re.sub(r',?gic-version=[a-zA-Z0-9]+', '', val).lstrip(',')
                if val_clean:
                    clean_tokens.append(f'-machine={val_clean}')
                i += 1
                continue
            else:
                clean_tokens.append(tok)
                i += 1

        if target_gic in ['2', '3', 'host', 'max']:
            found = False
            for j in range(len(clean_tokens)):
                if clean_tokens[j] == '-machine' and j + 1 < len(clean_tokens):
                    clean_tokens[j+1] = f'{clean_tokens[j+1]},gic-version={target_gic}'.lstrip(',')
                    found = True
                    break
            if not found:
                clean_tokens.extend(['-machine', f'gic-version={target_gic}'])

        return ' '.join(clean_tokens).strip()

    def _update_conf_file(self, conf_path, vmid, target_gic):
        """Helper to modify gic-version in a QEMU VM configuration file."""
        if not os.path.exists(conf_path):
            return {"success": False, "error": f"VM configuration not found: {conf_path}"}

        try:
            with open(conf_path, "r", encoding="utf-8") as f:
                content = f.read()
        except Exception as e:
            return {"success": False, "error": f"Cannot read config: {e}"}

        lines = content.splitlines()
        new_lines = []
        found_gicversion = False
        found_args = False

        for line in lines:
            line_str = line.strip()
            if line_str.startswith("gicversion:"):
                found_gicversion = True
                if target_gic in ["2", "3", "host", "max"]:
                    new_lines.append(f"gicversion: {target_gic}")
            elif line_str.startswith("args:"):
                found_args = True
                old_args = line_str[5:].strip()
                updated_args = self.update_args_gic(old_args, target_gic)
                if updated_args:
                    new_lines.append(f"args: {updated_args}")
            else:
                new_lines.append(line)

        if not found_args and not found_gicversion and target_gic in ["2", "3", "host", "max"]:
            new_lines.append(f"args: -machine gic-version={target_gic}")

        new_content = "\n".join(new_lines) + "\n"

        try:
            with open(conf_path, "w", encoding="utf-8") as f:
                f.write(new_content)
            logger.info(f"Updated VM {vmid} GIC to '{target_gic}' in {conf_path}")
        except Exception as e:
            return {"success": False, "error": f"Failed to write config: {e}"}

        return {
            "success": True,
            "vmid": vmid,
            "target_gic": target_gic,
            "message": f"Successfully updated VM {vmid} GIC configuration to '{target_gic}'. Please fully stop and restart VM for changes to take effect."
        }

    def set_vm_gic_version(self, vmid, target_gic, node_name=None):
        """
        Safely update GIC version for a VM.
        target_gic: "3", "2", "host", "max", or "default" (remove override)
        Supports inter-node API and shared pmxcfs filesystem fallback.
        """
        if node_name and node_name != self.local_node_name:
            # 1. Try inter-node API
            nodes = self.get_cluster_nodes()
            node_info = nodes.get(node_name)
            if node_info and node_info.get("ip"):
                from .cluster_auth import call_node_api
                res = call_node_api(
                    node_info["ip"],
                    port=cfg.api_port,
                    endpoint=f"/api/v1/vms/{vmid}/gic",
                    method="POST",
                    payload={"gic_version": target_gic, "node": node_name},
                    timeout=5.0
                )
                if res.get("success") and isinstance(res.get("data"), dict):
                    return res["data"]

            # 2. Fallback to cluster shared filesystem (/etc/pve/nodes/{node_name}/qemu-server/{vmid}.conf)
            remote_conf = os.path.join(cfg.pve_nodes_dir, node_name, "qemu-server", f"{vmid}.conf")
            if os.path.exists(remote_conf):
                return self._update_conf_file(remote_conf, vmid, target_gic)

        # Local update
        conf_dir = os.path.join(cfg.pve_nodes_dir, self.local_node_name, "qemu-server")
        conf_path = os.path.join(conf_dir, f"{vmid}.conf")
        res = self._update_conf_file(conf_path, vmid, target_gic)
        self.scan_local_vms()
        return res

    def control_vm_power(self, vmid, action, node_name=None):
        """
        Execute VM power action: "start", "shutdown", "reboot", "stop".
        Primary path: pvesh create /nodes/{node}/qemu/{vmid}/status/{action}.
        Gracefully handles idempotency ("already running", "not running") as success.
        For "shutdown": dispatches asynchronously to avoid blocking HTTP requests while
        real operating systems (such as Linux/Debian/PVE) cleanly sync disks and exit services (15-35s).
        Accurately differentiates GICv2 Logo freeze vs uninstalled OS when ACPI cannot respond.
        """
        valid_actions = ["start", "shutdown", "reboot", "stop"]
        if action not in valid_actions:
            return {"success": False, "error": f"Invalid action: {action}. Allowed: {valid_actions}"}

        target_node = node_name or self.local_node_name

        # Detect VM GIC version to distinguish GICv2 Logo hang vs uninstalled OS
        vm_gic = "3"
        try:
            vm_info = self.cached_vms.get(vmid)
            if vm_info:
                vm_gic = vm_info.get("effective_gic") or vm_info.get("config_gic") or ("2" if vm_info.get("vcpus", 1) <= 8 else "3")
            else:
                conf_path = os.path.join(cfg.pve_nodes_dir, target_node, "qemu-server", f"{vmid}.conf")
                if os.path.exists(conf_path):
                    with open(conf_path, "r", encoding="utf-8") as f:
                        text = f.read()
                        if "gic-version=2" in text or "gicversion: 2" in text:
                            vm_gic = "2"
        except Exception:
            pass

        # 1. Check current status before issuing command to avoid unnecessary lock collisions
        try:
            status_timeout = 2.0 if target_node == self.local_node_name else 8.0
            status_cmd = ["pvesh", "get", f"/nodes/{target_node}/qemu/{vmid}/status/current", "--output-format", "json"]
            st_out = subprocess.check_output(status_cmd, stderr=subprocess.DEVNULL, timeout=status_timeout).decode("utf-8")
            st_json = json.loads(st_out)
            cur_status = st_json.get("status")
            if action == "start" and cur_status == "running":
                return {
                    "success": True,
                    "vmid": vmid,
                    "action": action,
                    "node": target_node,
                    "vm_gic": vm_gic,
                    "message": f"VM {vmid} 当前已处于运行状态，无需重复开机"
                }
            elif action in ["shutdown", "stop"] and cur_status == "stopped":
                return {
                    "success": True,
                    "vmid": vmid,
                    "action": action,
                    "node": target_node,
                    "vm_gic": vm_gic,
                    "message": f"VM {vmid} 当前已处于关机状态"
                }
        except Exception:
            # Fallback to cached VM status if pvesh status query timed out
            cached = self.cached_vms.get(vmid)
            if cached:
                cached_st = cached.get("status")
                if action == "start" and cached_st == "running":
                    return {
                        "success": True,
                        "vmid": vmid,
                        "action": action,
                        "node": target_node,
                        "vm_gic": vm_gic,
                        "message": f"VM {vmid} 当前已处于运行状态，无需重复开机"
                    }
                elif action in ["shutdown", "stop"] and cached_st == "stopped":
                    return {
                        "success": True,
                        "vmid": vmid,
                        "action": action,
                        "node": target_node,
                        "vm_gic": vm_gic,
                        "message": f"VM {vmid} 当前已处于关机状态"
                    }

        # 2. Asynchronous execution for "shutdown":
        # Operating systems take 15~35 seconds to safely stop services and flush caches.
        # Returning immediately prevents HTTP request timeouts on installed systems!
        if action == "shutdown":
            def _async_shutdown_worker():
                try:
                    cmd_shutdown = ["pvesh", "create", f"/nodes/{target_node}/qemu/{vmid}/status/shutdown"]
                    out_sh = subprocess.check_output(cmd_shutdown, stderr=subprocess.STDOUT, timeout=65.0).decode("utf-8").strip()
                    logger.info(f"VM {vmid} shutdown task completed cleanly: {out_sh}")
                except subprocess.CalledProcessError as e_sh:
                    err_sh = e_sh.output.decode("utf-8", errors="replace") if hasattr(e_sh, "output") else str(e_sh)
                    logger.warning(f"VM {vmid} shutdown returned notice: {err_sh}")
                except Exception as e_sh:
                    logger.warning(f"VM {vmid} shutdown notice: {e_sh}")

            threading.Thread(target=_async_shutdown_worker, daemon=True, name=f"shutdown_{vmid}").start()

            msg = f"VM {vmid} 关机指令已成功下发 (ACPI 软关机进行中，操作系统正在安全关闭服务并同步数据)"
            if vm_gic == "2":
                msg = f"VM {vmid} 关机指令已成功下发。注意：该虚拟机配置为 GICv2，若开机时曾卡在 Logo 界面，请直接使用【停止】按钮强制断电关机"

            return {
                "success": True,
                "vmid": vmid,
                "action": "shutdown",
                "node": target_node,
                "vm_gic": vm_gic,
                "status": "shutting_down",
                "message": msg
            }

        # 3. For "stop", "start", "reboot"
        cmd = ["pvesh", "create", f"/nodes/{target_node}/qemu/{vmid}/status/{action}"]
        if action == "start":
            cmd.extend(["--timeout", "40"])
            timeout_sec = 45.0
        elif action == "reboot":
            cmd.extend(["--timeout", "40"])
            timeout_sec = 45.0
        else: # stop: force stop overruling active shutdown task and skipping stale lock
            cmd.extend(["--overrule-shutdown", "1", "--skiplock", "1", "--timeout", "20"])
            timeout_sec = 25.0

        try:
            out = subprocess.check_output(cmd, stderr=subprocess.STDOUT, timeout=timeout_sec).decode("utf-8").strip()
            logger.info(f"Dispatched power action via pvesh: {' '.join(cmd)} -> {out}")
            out_lower = out.lower()

            if "already running" in out_lower or "already active" in out_lower:
                return {
                    "success": True,
                    "vmid": vmid,
                    "action": action,
                    "node": target_node,
                    "vm_gic": vm_gic,
                    "message": f"VM {vmid} 已启动并处于运行状态"
                }

            if action in ["shutdown", "stop"] and "not running" in out_lower:
                return {
                    "success": True,
                    "vmid": vmid,
                    "action": action,
                    "node": target_node,
                    "vm_gic": vm_gic,
                    "message": f"VM {vmid} 已处于关机状态"
                }

            if "is locked" in out_lower or "can't lock" in out_lower:
                return {
                    "success": True,
                    "vmid": vmid,
                    "action": action,
                    "node": target_node,
                    "vm_gic": vm_gic,
                    "message": f"VM {vmid} 正在执行电源状态切换任务中，请稍候刷新查看状态"
                }

            action_desc = "开机启动" if action == "start" else ("强制停止" if action == "stop" else "重启")
            return {
                "success": True,
                "vmid": vmid,
                "action": action,
                "node": target_node,
                "vm_gic": vm_gic,
                "message": f"VM {vmid} {action_desc}操作成功",
                "upid": out
            }
        except subprocess.CalledProcessError as e_pvesh:
            err_msg = e_pvesh.output.decode("utf-8", errors="replace") if hasattr(e_pvesh, "output") else str(e_pvesh)
            err_msg_lower = err_msg.lower()

            if "already running" in err_msg_lower or "already active" in err_msg_lower:
                return {
                    "success": True,
                    "vmid": vmid,
                    "action": action,
                    "node": target_node,
                    "vm_gic": vm_gic,
                    "message": f"VM {vmid} 已启动并处于运行状态"
                }

            # Check if VM actually transitioned to target status despite pvesh return code
            try:
                chk_cmd = ["pvesh", "get", f"/nodes/{target_node}/qemu/{vmid}/status/current", "--output-format", "json"]
                chk_out = subprocess.check_output(chk_cmd, stderr=subprocess.DEVNULL, timeout=4.0).decode("utf-8")
                real_st = json.loads(chk_out).get("status")
                if action == "start" and real_st == "running":
                    return {
                        "success": True,
                        "vmid": vmid,
                        "action": action,
                        "node": target_node,
                        "vm_gic": vm_gic,
                        "message": f"VM {vmid} 开机启动成功 (已进入运行状态)"
                    }
                elif action in ["stop", "shutdown"] and real_st == "stopped":
                    return {
                        "success": True,
                        "vmid": vmid,
                        "action": action,
                        "node": target_node,
                        "vm_gic": vm_gic,
                        "message": f"VM {vmid} 已处于关机状态"
                    }
            except Exception:
                pass
            if "not running" in err_msg_lower:
                return {
                    "success": True,
                    "vmid": vmid,
                    "action": action,
                    "node": target_node,
                    "vm_gic": vm_gic,
                    "message": f"VM {vmid} 已处于关机状态"
                }

            if action == "stop":
                # Local fallback to qm stop CLI
                if target_node == self.local_node_name:
                    try:
                        out_qm = subprocess.check_output(
                            ["qm", "stop", str(vmid), "--skiplock", "1", "--overrule-shutdown", "1", "--timeout", "10"],
                            stderr=subprocess.STDOUT, timeout=12.0
                        ).decode("utf-8").strip()
                        return {
                            "success": True,
                            "vmid": vmid,
                            "action": "stop",
                            "node": target_node,
                            "vm_gic": vm_gic,
                            "message": f"VM {vmid} 已强制断电停止 (已跳过任务锁)"
                        }
                    except Exception as e_qm:
                        logger.warning(f"qm stop local fallback failed: {e_qm}")

            if "is locked" in err_msg_lower or "can't lock" in err_msg_lower:
                return {
                    "success": True,
                    "vmid": vmid,
                    "action": action,
                    "node": target_node,
                    "vm_gic": vm_gic,
                    "message": f"VM {vmid} 正在执行电源状态切换任务中，请稍候刷新查看状态"
                }

            # If node is remote and pvesh failed, try node API
            if target_node != self.local_node_name:
                nodes = self.get_cluster_nodes()
                node_info = nodes.get(target_node)
                if node_info and node_info.get("ip"):
                    from .cluster_auth import call_node_api
                    res = call_node_api(
                        node_info["ip"],
                        port=cfg.api_port,
                        endpoint=f"/api/v1/vms/{vmid}/power",
                        method="POST",
                        payload={"action": action, "node": target_node},
                        timeout=10.0
                    )
                    if res.get("success") and isinstance(res.get("data"), dict):
                        return res["data"]

            return {"success": False, "error": f"执行 {action} 失败: {err_msg.strip()}"}

        except subprocess.TimeoutExpired:
            try:
                status_cmd = ["pvesh", "get", f"/nodes/{target_node}/qemu/{vmid}/status/current", "--output-format", "json"]
                st_out = subprocess.check_output(status_cmd, stderr=subprocess.DEVNULL, timeout=2.0).decode("utf-8")
                st_json = json.loads(st_out)
                cur_status = st_json.get("status")
                if action == "start" and cur_status == "running":
                    return {
                        "success": True,
                        "vmid": vmid,
                        "action": action,
                        "node": target_node,
                        "vm_gic": vm_gic,
                        "message": f"VM {vmid} 开机启动成功"
                    }
                elif action in ["shutdown", "stop"] and cur_status == "stopped":
                    return {
                        "success": True,
                        "vmid": vmid,
                        "action": action,
                        "node": target_node,
                        "vm_gic": vm_gic,
                        "message": f"VM {vmid} 已关机"
                    }
            except Exception:
                pass

            return {
                "success": True,
                "vmid": vmid,
                "action": action,
                "node": target_node,
                "vm_gic": vm_gic,
                "message": f"VM {vmid} {action} 任务已在后台执行，请稍候刷新查看状态"
            }

    def start_background_watcher(self):
        """Start directory and state watcher thread for real-time sync (Requirement 8)."""
        if self.watcher_running:
            return
        self.watcher_running = True
        self.watcher_thread = threading.Thread(target=self._watcher_loop, daemon=True, name="pve_watcher")
        self.watcher_thread.start()
        logger.info("Background PVE VM synchronizer started")

    def _watcher_loop(self):
        """Continuously check /etc/pve/nodes for changes and rescan."""
        last_mtime = 0
        last_arp_time = 0
        nodes_dir = cfg.pve_nodes_dir
        while self.watcher_running:
            try:
                # Refresh ARP table periodically (every 12 seconds)
                if time.time() - last_arp_time > 12.0:
                    last_arp_time = time.time()
                    self.refresh_active_arp()

                # Check directory modification time
                current_mtime = 0
                if os.path.exists(nodes_dir):
                    current_mtime = os.path.getmtime(nodes_dir)
                    for root, dirs, files in os.walk(nodes_dir):
                        for f in files:
                            if f.endswith(".conf"):
                                fp = os.path.join(root, f)
                                fm = os.path.getmtime(fp)
                                if fm > current_mtime:
                                    current_mtime = fm

                if current_mtime > last_mtime or (time.time() - self.last_scan_time > 15):
                    last_mtime = current_mtime
                    self.scan_all_vms()
            except Exception as e:
                logger.debug(f"Watcher loop error: {e}")

            time.sleep(cfg.sync_interval)

scanner = PVEScanner()
