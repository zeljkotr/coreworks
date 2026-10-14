import platform
import shutil
import socket
import time
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, Depends

from coreworks_api.auth import get_current_user

router = APIRouter(
    prefix="/local-infrastructure",
    tags=["local-infrastructure"],
)


def cpu_snapshot():
    values = Path("/proc/stat").read_text().splitlines()[0].split()[1:]
    numbers = [int(value) for value in values]
    idle = numbers[3] + (numbers[4] if len(numbers) > 4 else 0)
    return sum(numbers), idle


def cpu_usage():
    first_total, first_idle = cpu_snapshot()
    time.sleep(0.1)
    second_total, second_idle = cpu_snapshot()
    total_delta = second_total - first_total
    idle_delta = second_idle - first_idle
    if total_delta <= 0:
        return 0.0
    return round(100 * (total_delta - idle_delta) / total_delta, 1)


@router.get("")
def local_infrastructure(_user=Depends(get_current_user)):
    memory = {}
    for line in Path("/proc/meminfo").read_text().splitlines():
        key, value = line.split(":", 1)
        memory[key] = int(value.strip().split()[0]) * 1024

    total_ram = memory.get("MemTotal", 0)
    available_ram = memory.get("MemAvailable", 0)
    used_ram = max(0, total_ram - available_ram)
    disk = shutil.disk_usage("/")
    os_info = {}
    release = Path("/etc/os-release")
    if release.exists():
        for line in release.read_text().splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                os_info[key] = value.strip().strip('"')

    uptime = float(Path("/proc/uptime").read_text().split()[0])
    return {
        "hostname": socket.gethostname(),
        "operating_system": os_info.get("PRETTY_NAME", platform.platform()),
        "cpu_percent": cpu_usage(),
        "ram_percent": round(used_ram * 100 / total_ram, 1) if total_ram else 0,
        "ram_used_bytes": used_ram,
        "ram_total_bytes": total_ram,
        "disks": [{
            "mountpoint": "/",
            "used_percent": round(disk.used * 100 / disk.total, 1),
            "used_bytes": disk.used,
            "total_bytes": disk.total,
        }],
        "uptime_seconds": int(uptime),
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }
