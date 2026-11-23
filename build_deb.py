#!/usr/bin/env python3
"""
Cross-Platform Debian (.deb) Package Builder for pve-gic-manager.
Produces fully compliant Debian binary packages on Windows or Linux without external dependencies.
"""
import os
import sys
import io
import time
import tarfile
import shutil

PACKAGE_NAME = "pve-gic-manager"
VERSION = "1.0.0"
ARCH = "all"
OUTPUT_DEB_NAME = f"{PACKAGE_NAME}_{VERSION}_{ARCH}.deb"

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))

def create_ar_archive(output_path, files):
    """
    Create a standard Debian binary 'ar' archive.
    files: list of tuples (filename_str, bytes_content)
    """
    with open(output_path, "wb") as ar:
        # Global ar signature "!<arch>\n"
        ar.write(b"!<arch>\n")
        for filename, data in files:
            # ar header format:
            # 0-15:  file identifier (ASCII, space padded)
            # 16-27: file modification timestamp (decimal, space padded)
            # 28-33: owner ID (decimal, space padded)
            # 34-39: group ID (decimal, space padded)
            # 40-47: file mode (octal, space padded)
            # 48-57: file size (decimal, space padded)
            # 58-59: header trailer `\x60\n`
            name_padded = f"{filename:<16}".encode("ascii")
            mtime_padded = f"{int(time.time()):<12}".encode("ascii")
            owner_padded = b"0     "
            group_padded = b"0     "
            mode_padded = b"100644  "
            size_padded = f"{len(data):<10}".encode("ascii")
            trailer = b"`\n"
            
            header = name_padded + mtime_padded + owner_padded + group_padded + mode_padded + size_padded + trailer
            ar.write(header)
            ar.write(data)
            # ar requires 2-byte alignment padding
            if len(data) % 2 != 0:
                ar.write(b"\n")

def make_tar_gz(items):
    """
    items: list of dicts:
      {"name": str, "content": bytes or filepath, "mode": int, "is_dir": bool}
    Returns gzipped tar bytes.
    """
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for item in items:
            name = item["name"]
            mode = item.get("mode", 0o644)
            ti = tarfile.TarInfo(name=name)
            ti.mtime = int(time.time())
            ti.uid = 0
            ti.gid = 0
            ti.uname = "root"
            ti.gname = "root"

            if item.get("is_dir"):
                ti.type = tarfile.DIRTYPE
                ti.mode = mode if mode else 0o755
                tar.addfile(ti)
            elif "filepath" in item:
                fp = item["filepath"]
                ti.size = os.path.getsize(fp)
                ti.mode = mode
                with open(fp, "rb") as f:
                    tar.addfile(ti, f)
            elif "content" in item:
                c = item["content"]
                if isinstance(c, str):
                    c = c.encode("utf-8")
                ti.size = len(c)
                ti.mode = mode
                tar.addfile(ti, io.BytesIO(c))
    return buf.getvalue()

def build_deb():
    print(f"[*] Building Debian package {OUTPUT_DEB_NAME}...")

    # 1. debian-binary content
    debian_binary = b"2.0\n"

    # 2. Build control.tar.gz
    debian_dir = os.path.join(PROJECT_ROOT, "debian")
    control_items = [
        {"name": "./", "is_dir": True, "mode": 0o755},
        {"name": "./control", "filepath": os.path.join(debian_dir, "control"), "mode": 0o644},
        {"name": "./postinst", "filepath": os.path.join(debian_dir, "postinst"), "mode": 0o755},
        {"name": "./prerm", "filepath": os.path.join(debian_dir, "prerm"), "mode": 0o755},
        {"name": "./postrm", "filepath": os.path.join(debian_dir, "postrm"), "mode": 0o755},
    ]
    control_tar_gz = make_tar_gz(control_items)
    print(f"    [+] control.tar.gz built ({len(control_tar_gz)} bytes)")

    # 3. Build data.tar.gz
    data_items = [
        {"name": "./", "is_dir": True, "mode": 0o755},
        {"name": "./usr", "is_dir": True, "mode": 0o755},
        {"name": "./usr/bin", "is_dir": True, "mode": 0o755},
        {"name": "./usr/share", "is_dir": True, "mode": 0o755},
        {"name": "./usr/share/pve-gic-manager", "is_dir": True, "mode": 0o755},
        {"name": "./etc", "is_dir": True, "mode": 0o755},
        {"name": "./etc/systemd", "is_dir": True, "mode": 0o755},
        {"name": "./etc/systemd/system", "is_dir": True, "mode": 0o755},
        {"name": "./etc/pve-gic-manager", "is_dir": True, "mode": 0o755},
        
        # Binary CLI
        {"name": "./usr/bin/pve-gic-manager", "filepath": os.path.join(PROJECT_ROOT, "pve-gic-manager"), "mode": 0o755},
        # Systemd service
        {"name": "./etc/systemd/system/pve-gic-manager.service", "filepath": os.path.join(debian_dir, "pve-gic-manager.service"), "mode": 0o644},
    ]

    # Add python package files
    src_pkg_dir = os.path.join(PROJECT_ROOT, "pve_gic_manager")
    for root, dirs, files in os.walk(src_pkg_dir):
        rel_dir = os.path.relpath(root, PROJECT_ROOT).replace("\\", "/")
        target_dir = f"./usr/share/pve-gic-manager/{rel_dir}"
        data_items.append({"name": target_dir, "is_dir": True, "mode": 0o755})
        for f in files:
            if f.endswith(".pyc") or f == "__pycache__":
                continue
            src_file = os.path.join(root, f)
            target_file = f"{target_dir}/{f}"
            data_items.append({"name": target_file, "filepath": src_file, "mode": 0o644})

    data_tar_gz = make_tar_gz(data_items)
    print(f"    [+] data.tar.gz built ({len(data_tar_gz)} bytes, {len(data_items)} files)")

    # 4. Assemble .deb ar archive
    deb_files = [
        ("debian-binary", debian_binary),
        ("control.tar.gz", control_tar_gz),
        ("data.tar.gz", data_tar_gz)
    ]
    out_deb_path = os.path.join(PROJECT_ROOT, OUTPUT_DEB_NAME)
    create_ar_archive(out_deb_path, deb_files)

    print(f"[SUCCESS] Deb package successfully created at: {out_deb_path}")
    print(f"          File size: {os.path.getsize(out_deb_path)} bytes")

if __name__ == "__main__":
    build_deb()
