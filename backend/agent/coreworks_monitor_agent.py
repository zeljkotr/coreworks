#!/usr/bin/env python3
"""CoreWorks Monitor agent. Read-only metrics collection; no remote command execution."""

import json
import os
import platform
import socket
import sys
import time
import urllib.error
import urllib.request

import psutil

API_URL = os.environ.get("COREWORKS_MONITOR_URL", "").rstrip("/")
TOKEN = os.environ.get("COREWORKS_MONITOR_TOKEN", "")
INTERVAL = max(15, int(os.environ.get("COREWORKS_MONITOR_INTERVAL", "30")))
VERSION = "1.0.0"


def collect():
    memory = psutil.virtual_memory()
    disks = []
    seen = set()

    for partition in psutil.disk_partitions(all=False):
        mount = partition.mountpoint
        if mount in seen:
            continue
        seen.add(mount)
        try:
            usage = psutil.disk_usage(mount)
            disks.append({
                "mountpoint": mount,
                "total_bytes": usage.total,
                "used_bytes": usage.used,
                "free_bytes": usage.free,
            })
        except (PermissionError, OSError):
            continue

    return {
        "cpu_percent": psutil.cpu_percent(interval=1),
        "memory_total_bytes": memory.total,
        "memory_used_bytes": memory.used,
        "disk": disks,
        "uptime_seconds": max(0, int(time.time() - psutil.boot_time())),
        "os_name": f"{platform.system()} {platform.release()} ({platform.machine()})",
        "hostname": socket.gethostname(),
        "agent_version": VERSION,
    }


def send(payload):
    request = urllib.request.Request(
        API_URL + "/monitor/agent/metrics",
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": "Bearer " + TOKEN,
            "Content-Type": "application/json",
            "User-Agent": "CoreWorks-Monitor-Agent/" + VERSION,
        },
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=15) as response:
        return response.status


def main():
    if not API_URL.startswith("https://") and not API_URL.startswith("http://127.0.0.1"):
        print("COREWORKS_MONITOR_URL mora koristiti HTTPS (osim lokalnog testiranja).", file=sys.stderr)
        return 2
    if not TOKEN:
        print("Nedostaje COREWORKS_MONITOR_TOKEN.", file=sys.stderr)
        return 2

    while True:
        try:
            send(collect())
            print("CoreWorks Monitor metrics sent.", flush=True)
        except (OSError, ValueError, urllib.error.URLError) as exc:
            print(f"Metrics send failed: {exc}", file=sys.stderr, flush=True)
        time.sleep(INTERVAL)


if __name__ == "__main__":
    raise SystemExit(main())
