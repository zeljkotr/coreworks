from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
import ipaddress
import re
import socket
import ssl

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session
from pydantic import BaseModel, Field

from coreworks_api.auth import get_current_user, get_db
from coreworks_api.models import GuardianFinding, GuardianScan

router = APIRouter(prefix="/guardian", tags=["guardian"])

DEFAULT_PORTS = (
    21, 22, 23, 25, 53, 80, 110, 139,
    143, 443, 445, 3306, 3389, 5432, 8080, 8443,
)

SERVICE_NAMES = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    6379: "Redis",
    8080: "HTTP alternate",
    8443: "HTTPS alternate",
    9200: "Elasticsearch",
    27017: "MongoDB",
}

EXPOSURE_ADVICE = {
    21: ("medium", "FTP may transmit credentials without encryption. Prefer SFTP or secured FTPS."),
    23: ("high", "Telnet is unencrypted. Disable it and use SSH."),
    139: ("medium", "Restrict NetBIOS to trusted networks if required."),
    445: ("medium", "Restrict SMB to trusted networks and disable it where unnecessary."),
    3306: ("medium", "Restrict database access to trusted application hosts."),
    3389: ("medium", "Restrict RDP to trusted management networks and enforce strong authentication."),
    5432: ("medium", "Restrict database access to trusted application hosts."),
    6379: ("medium", "Restrict Redis to trusted application hosts."),
    9200: ("medium", "Restrict Elasticsearch to trusted application hosts."),
    27017: ("medium", "Restrict MongoDB to trusted application hosts."),
}


class ScanRequest(BaseModel):
    target: str = Field(min_length=1, max_length=100)
    ports: list[int] = Field(default_factory=lambda: list(DEFAULT_PORTS), max_length=32)


def parse_target(target: str) -> list[str]:
    """Accept IP addresses or small CIDR networks, never DNS names."""
    try:
        network = ipaddress.ip_network(target.strip(), strict=False)
    except ValueError:
        raise ValueError("Enter a valid IP address or CIDR network.") from None

    if network.num_addresses > 256:
        raise ValueError("A scan may contain at most 256 IP addresses.")

    hosts = list(network.hosts())
    if not hosts:
        hosts = [network.network_address]

    for address in hosts:
        if address.is_global:
            raise ValueError(
                "Public IP addresses are not accepted. Scan an authorized private or internal network."
            )
        if address.is_multicast or address.is_unspecified:
            raise ValueError("Multicast and unspecified addresses cannot be scanned.")

    return [str(address) for address in hosts]


def validate_ports(ports: list[int]) -> list[int]:
    if not ports:
        raise ValueError("Select at least one TCP port.")
    if len(ports) > 32:
        raise ValueError("A scan may check at most 32 ports.")
    if len(set(ports)) != len(ports):
        raise ValueError("Duplicate ports are not allowed.")
    if any(port < 1 or port > 65535 for port in ports):
        raise ValueError("Ports must be between 1 and 65535.")
    return ports


def probe_tcp(host: str, port: int) -> bool:
    try:
        with socket.create_connection((host, port), timeout=0.4):
            return True
    except (OSError, TimeoutError):
        return False



def parse_service_banner(banner: str, fallback: str) -> tuple[str, str]:
    """Extract a product/version hint from a protocol banner or HTTP response."""
    clean = " ".join(banner.replace("\x00", " ").split())[:500]
    if not clean:
        return fallback, "Unknown"

    patterns = (
        (r"SSH-[0-9.]+-OpenSSH[_-]([^\s]+)", "OpenSSH"),
        (r"(?i)\bnginx/([0-9][\w.+~-]*)", "nginx"),
        (r"(?i)\bApache(?:/|\s+)([0-9][\w.+~-]*)", "Apache HTTP Server"),
        (r"(?i)\bMicrosoft-IIS/([0-9][\w.+~-]*)", "Microsoft IIS"),
        (r"(?i)\bOpenSSL/([0-9][\w.+~-]*)", "OpenSSL"),
        (r"(?i)\bvsFTPd\s*([0-9][\w.+~-]*)", "vsFTPd"),
        (r"(?i)\bProFTPD\s*([0-9][\w.+~-]*)", "ProFTPD"),
        (r"(?i)\bRedis(?:\s+server)?\s*v?([0-9][\w.+~-]*)", "Redis"),
        (r"(?i)\bPostgreSQL\s+([0-9][\w.+~-]*)", "PostgreSQL"),
        (r"(?i)\bMySQL\s+([0-9][\w.+~-]*)", "MySQL"),
    )
    for pattern, product in patterns:
        match = re.search(pattern, clean)
        if match:
            return product, match.group(1)

    return fallback, "Unknown"


def fingerprint_service(host: str, port: int) -> dict:
    """Perform a short, non-authenticated protocol greeting/version probe."""
    fallback = SERVICE_NAMES.get(port, "Unknown TCP service")
    evidence = ""
    product = fallback
    version = "Unknown"
    confidence = "low"

    try:
        with socket.create_connection((host, port), timeout=0.6) as raw:
            raw.settimeout(0.6)

            if port in (80, 8080, 8000, 8888):
                raw.sendall(
                    f"HEAD / HTTP/1.0\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode()
                )
                evidence = raw.recv(4096).decode("latin-1", errors="replace")

            elif port in (443, 8443):
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                with context.wrap_socket(raw, server_hostname=host) as secure:
                    tls_version = secure.version() or "TLS"
                    try:
                        secure.sendall(
                            f"HEAD / HTTP/1.0\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode()
                        )
                        evidence = secure.recv(4096).decode("latin-1", errors="replace")
                    except (OSError, TimeoutError, ssl.SSLError):
                        evidence = ""
                    if evidence:
                        evidence = f"TLS {tls_version}; {evidence}"
                    else:
                        evidence = f"TLS handshake negotiated {tls_version}"
                        product = "TLS service"
                        version = tls_version
                        confidence = "medium"

            elif port == 6379:
                raw.sendall(b"PING\r\n")
                evidence = raw.recv(1024).decode("latin-1", errors="replace")

            else:
                try:
                    evidence = raw.recv(2048).decode("latin-1", errors="replace")
                except (OSError, TimeoutError):
                    evidence = ""

        product, version = parse_service_banner(evidence, fallback)
        if evidence.strip():
            confidence = "medium"
        if product != fallback and version != "Unknown":
            confidence = "high"

    except (OSError, TimeoutError, ssl.SSLError, ValueError):
        pass

    evidence = " ".join(evidence.replace("\x00", " ").split())[:300]
    return {
        "product": product,
        "version": version,
        "evidence": evidence or "Service accepted a TCP connection; no banner returned.",
        "confidence": confidence,
    }

def describe_exposure(host: str, port: int) -> dict:
    severity, recommendation = EXPOSURE_ADVICE.get(
        port,
        ("info", "Verify that this service is required and restricted by firewall rules."),
    )
    fingerprint = fingerprint_service(host, port)
    return {
        "host": host,
        "port": port,
        "service": SERVICE_NAMES.get(port, "Unknown TCP service"),
        "product": fingerprint["product"],
        "version": fingerprint["version"],
        "evidence": fingerprint["evidence"],
        "confidence": fingerprint["confidence"],
        "severity": severity,
        "title": "Open TCP port",
        "recommendation": recommendation,
    }


@router.get("/status")
def guardian_status(current_user=Depends(get_current_user)) -> dict:
    return {
        "module": "Guardian",
        "status": "ready",
        "scanner": "tcp-connect",
        "authenticated": True,
    }


@router.post("/scan")
def scan_target(
    request: ScanRequest,
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    try:
        hosts = parse_target(request.target)
        ports = validate_ports(request.ports)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None

    if len(hosts) * len(ports) > 4096:
        raise HTTPException(
            status_code=422,
            detail="This scan exceeds 4096 host-port checks. Use a smaller network or fewer ports.",
        )

    jobs = {}
    findings = []

    with ThreadPoolExecutor(max_workers=64) as executor:
        for host in hosts:
            for port in ports:
                future = executor.submit(probe_tcp, host, port)
                jobs[future] = (host, port)

        for future in as_completed(jobs):
            host, port = jobs[future]
            try:
                is_open = future.result()
            except Exception:
                is_open = False

            if is_open:
                findings.append(describe_exposure(host, port))

    findings.sort(
        key=lambda item: (
            ipaddress.ip_address(item["host"]).version,
            int(ipaddress.ip_address(item["host"])),
            item["port"],
        )
    )

    scanned_at = datetime.now(timezone.utc)
    scan = GuardianScan(
        user_id=current_user.id, target=request.target,
        scanned_at=scanned_at, hosts_checked=len(hosts),
        ports_per_host=len(ports),
        checks_completed=len(hosts) * len(ports),
        open_ports=len(findings),
    )
    db.add(scan)
    db.flush()
    for finding in findings:
        db.add(GuardianFinding(scan_id=scan.id, **finding))
    db.commit()
    return {
        "id": scan.id,
        "target": request.target,
        "scanned_at": scanned_at.isoformat(),
        "hosts_checked": len(hosts),
        "ports_per_host": len(ports),
        "checks_completed": len(hosts) * len(ports),
        "open_ports": len(findings),
        "findings": findings,
        "notice": (
            "Open ports are exposure indicators, not proof of a vulnerability. "
            "Verify findings against the target configuration."
        ),
    }


@router.get("/history")
def guardian_history(
    limit: int = 50,
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[dict]:
    if not 1 <= limit <= 100:
        raise HTTPException(status_code=422, detail="Limit must be between 1 and 100.")

    query = select(GuardianScan).order_by(GuardianScan.scanned_at.desc())
    if getattr(current_user, "role", "user") != "admin":
        query = query.where(GuardianScan.user_id == current_user.id)

    return [
        {
            "id": scan.id,
            "target": scan.target,
            "scanned_at": scan.scanned_at.isoformat(),
            "hosts_checked": scan.hosts_checked,
            "ports_per_host": scan.ports_per_host,
            "checks_completed": scan.checks_completed,
            "open_ports": scan.open_ports,
        }
        for scan in db.scalars(query.limit(limit)).all()
    ]


@router.get("/history/{scan_id}")
def guardian_scan_details(
    scan_id: int,
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    scan = db.get(GuardianScan, scan_id)
    if scan is None or (
        getattr(current_user, "role", "user") != "admin"
        and scan.user_id != current_user.id
    ):
        raise HTTPException(status_code=404, detail="Scan history entry not found.")

    findings = db.scalars(
        select(GuardianFinding).where(GuardianFinding.scan_id == scan.id)
    ).all()

    return {
        "id": scan.id,
        "target": scan.target,
        "scanned_at": scan.scanned_at.isoformat(),
        "hosts_checked": scan.hosts_checked,
        "ports_per_host": scan.ports_per_host,
        "checks_completed": scan.checks_completed,
        "open_ports": scan.open_ports,
        "findings": [
            {
                "host": f.host,
                "port": f.port,
                "service": f.service,
                "product": f.product,
                "version": f.version,
                "evidence": f.evidence,
                "confidence": f.confidence,
                "severity": f.severity,
                "title": f.title,
                "recommendation": f.recommendation,
            }
            for f in findings
        ],
    }


@router.get("/history/{scan_id}/comparison")
def guardian_scan_comparison(
    scan_id: int,
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    scan = db.get(GuardianScan, scan_id)
    if scan is None or (
        getattr(current_user, "role", "user") != "admin"
        and scan.user_id != current_user.id
    ):
        raise HTTPException(status_code=404, detail="Scan history entry not found.")

    previous_query = (
        select(GuardianScan)
        .where(
            GuardianScan.target == scan.target,
            GuardianScan.user_id == scan.user_id,
            GuardianScan.id < scan.id,
        )
        .order_by(GuardianScan.id.desc())
        .limit(1)
    )
    previous = db.scalars(previous_query).first()
    if previous is None:
        raise HTTPException(
            status_code=404,
            detail="No previous scan exists for this target and user.",
        )

    def load_findings(selected_scan_id: int) -> dict:
        rows = db.scalars(
            select(GuardianFinding).where(
                GuardianFinding.scan_id == selected_scan_id
            )
        ).all()
        return {
            (finding.host, finding.port): {
                "host": finding.host,
                "port": finding.port,
                "service": finding.service,
                "product": finding.product,
                "version": finding.version,
                "evidence": finding.evidence,
                "confidence": finding.confidence,
                "severity": finding.severity,
                "title": finding.title,
                "recommendation": finding.recommendation,
            }
            for finding in rows
        }

    old_findings = load_findings(previous.id)
    new_findings = load_findings(scan.id)

    current_results = []
    counts = {"new": 0, "resolved": 0, "unchanged": 0}

    for key, finding in sorted(new_findings.items()):
        status = "unchanged" if key in old_findings else "new"
        counts[status] += 1
        current_results.append({**finding, "status": status})

    resolved_results = []
    for key, finding in sorted(old_findings.items()):
        if key not in new_findings:
            counts["resolved"] += 1
            resolved_results.append({**finding, "status": "resolved"})

    return {
        "target": scan.target,
        "previous_scan": {
            "id": previous.id,
            "scanned_at": previous.scanned_at.isoformat(),
            "open_ports": previous.open_ports,
        },
        "current_scan": {
            "id": scan.id,
            "scanned_at": scan.scanned_at.isoformat(),
            "open_ports": scan.open_ports,
        },
        "summary": counts,
        "findings": current_results,
        "resolved_findings": resolved_results,
    }


@router.get("/trends")
def guardian_risk_trends(
    target: str,
    limit: int = 30,
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    if not target.strip() or len(target) > 100:
        raise HTTPException(status_code=400, detail="Invalid target.")
    if limit < 2 or limit > 100:
        raise HTTPException(
            status_code=400, detail="Limit must be between 2 and 100."
        )

    query = select(GuardianScan).where(GuardianScan.target == target.strip())
    if getattr(current_user, "role", "user") != "admin":
        query = query.where(GuardianScan.user_id == current_user.id)

    scans = list(
        db.scalars(
            query.order_by(GuardianScan.scanned_at.desc())
            .limit(limit)
        ).all()
    )
    scans.reverse()

    weights = {
        "critical": 10,
        "high": 7,
        "medium": 4,
        "low": 2,
        "info": 0,
    }
    trends = []

    for scan in scans:
        findings = db.scalars(
            select(GuardianFinding).where(
                GuardianFinding.scan_id == scan.id
            )
        ).all()

        severity_counts = {
            "critical": 0, "high": 0, "medium": 0,
            "low": 0, "info": 0,
        }
        score = 0

        for finding in findings:
            severity = (finding.severity or "info").lower()
            if severity not in severity_counts:
                severity = "info"
            severity_counts[severity] += 1
            score += weights[severity]

        trends.append({
            "id": scan.id,
            "scanned_at": scan.scanned_at.isoformat(),
            "hosts_checked": scan.hosts_checked,
            "open_ports": scan.open_ports,
            "findings_count": len(findings),
            "severity_counts": severity_counts,
            "risk_score": min(score, 100),
        })

    return {
        "target": target.strip(),
        "count": len(trends),
        "scans": trends,
        "risk_score_method": "Sum of finding severity weights, capped at 100.",
    }
