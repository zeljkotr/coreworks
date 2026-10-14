import pytest

from coreworks_api.guardian import parse_target, validate_ports, parse_service_banner, _cve_matches_cpe_version


def test_parse_single_private_ip():
    assert parse_target("192.168.2.10") == ["192.168.2.10"]


def test_parse_private_cidr():
    hosts = parse_target("192.168.2.0/30")
    assert hosts == ["192.168.2.1", "192.168.2.2"]


def test_accept_public_ip():
    assert parse_target("8.8.8.8") == ["8.8.8.8"]


def test_reject_public_cidr():
    with pytest.raises(ValueError, match="single IP"):
        parse_target("8.8.8.0/24")


def test_reject_oversized_network():
    with pytest.raises(ValueError, match="256"):
        parse_target("10.0.0.0/16")


def test_reject_hostname():
    with pytest.raises(ValueError, match="IP address"):
        parse_target("example.com")


def test_validate_ports():
    assert validate_ports([22, 443]) == [22, 443]


@pytest.mark.parametrize("ports", [[], [0], [65536], [22, 22], list(range(1, 34))])
def test_reject_invalid_port_lists(ports):
    with pytest.raises(ValueError):
        validate_ports(ports)


from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import Mock

from fastapi import HTTPException

from coreworks_api.guardian import guardian_scan_comparison


class FakeScalarResult:
    def __init__(self, first=None, all_rows=None):
        self.first_row = first
        self.all_rows = all_rows or []

    def first(self):
        return self.first_row

    def all(self):
        return self.all_rows


def fake_finding(port, host="192.168.2.20"):
    return SimpleNamespace(
        host=host,
        port=port,
        service="tcp",
        product="Test",
        version="1.0",
        evidence="test evidence",
        confidence="high",
        severity="info",
        title=f"Port {port}",
        recommendation="Review service",
    )


def test_guardian_comparison_reports_new_resolved_and_unchanged():
    timestamp = datetime(2026, 10, 14, tzinfo=timezone.utc)
    current = SimpleNamespace(
        id=2, user_id=7, target="192.168.2.20",
        scanned_at=timestamp, open_ports=2,
    )
    previous = SimpleNamespace(
        id=1, user_id=7, target="192.168.2.20",
        scanned_at=timestamp, open_ports=2,
    )
    db = Mock()
    db.get.return_value = current
    db.scalars.side_effect = [
        FakeScalarResult(first=previous),
        FakeScalarResult(all_rows=[fake_finding(21), fake_finding(22)]),
        FakeScalarResult(all_rows=[fake_finding(22), fake_finding(80)]),
    ]

    result = guardian_scan_comparison(
        2, SimpleNamespace(id=7, role="user"), db
    )

    assert result["summary"] == {"new": 1, "resolved": 1, "unchanged": 1}
    statuses = {
        (item["port"], item["status"])
        for item in result["findings"] + result["resolved_findings"]
    }
    assert statuses == {
        (80, "new"),
        (22, "unchanged"),
        (21, "resolved"),
    }


def test_guardian_comparison_requires_previous_scan():
    current = SimpleNamespace(
        id=2, user_id=7, target="192.168.2.20",
    )
    db = Mock()
    db.get.return_value = current
    db.scalars.return_value = FakeScalarResult(first=None)

    with pytest.raises(HTTPException) as exc:
        guardian_scan_comparison(
            2, SimpleNamespace(id=7, role="user"), db
        )

    assert exc.value.status_code == 404
    assert "No previous scan" in exc.value.detail


def test_guardian_comparison_hides_another_users_scan():
    db = Mock()
    db.get.return_value = SimpleNamespace(id=2, user_id=99)

    with pytest.raises(HTTPException) as exc:
        guardian_scan_comparison(
            2, SimpleNamespace(id=7, role="user"), db
        )

    assert exc.value.status_code == 404
    db.scalars.assert_not_called()


@pytest.mark.parametrize(
    ("banner", "fallback", "expected"),
    [
        ("SSH-2.0-OpenSSH_10.2p1 Ubuntu-2ubuntu3.6", "SSH", ("OpenSSH", "10.2p1")),
        ("nginx/1.26.2", "HTTP", ("nginx", "1.26.2")),
        ("Apache/2.4.58", "HTTP", ("Apache HTTP Server", "2.4.58")),
        ("OpenSSL/3.0.13", "HTTPS", ("OpenSSL", "3.0.13")),
        ("unknown server banner", "HTTP", ("HTTP", "Unknown")),
    ],
)
def test_parse_service_banner(banner, fallback, expected):
    assert parse_service_banner(banner, fallback) == expected



def test_guardian_cpe_exact_version_match():
    cve = {
        "configurations": [{
            "nodes": [{
                "cpeMatch": [{
                    "vulnerable": True,
                    "criteria": "cpe:2.3:a:openbsd:openssh:9.6p1:*:*:*:*:*:*:*",
                }]
            }]
        }]
    }
    assert _cve_matches_cpe_version(cve, "OpenSSH", "9.6p1")
    assert not _cve_matches_cpe_version(cve, "OpenSSH", "9.7p1")


def test_guardian_cpe_inclusive_version_end():
    cve = {
        "configurations": [{
            "nodes": [{
                "cpeMatch": [{
                    "vulnerable": True,
                    "criteria": "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*",
                    "versionEndIncluding": "9.6p1",
                }]
            }]
        }]
    }
    assert _cve_matches_cpe_version(cve, "OpenSSH", "9.6p1")
    assert not _cve_matches_cpe_version(cve, "OpenSSH", "9.7p1")


def test_guardian_cpe_exclusive_version_start():
    cve = {
        "configurations": [{
            "nodes": [{
                "cpeMatch": [{
                    "vulnerable": True,
                    "criteria": "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*",
                    "versionStartExcluding": "9.6",
                }]
            }]
        }]
    }
    assert not _cve_matches_cpe_version(cve, "OpenSSH", "9.6")
    assert _cve_matches_cpe_version(cve, "OpenSSH", "9.7")


def test_guardian_cpe_rejects_wrong_product():
    cve = {
        "configurations": [{
            "nodes": [{
                "cpeMatch": [{
                    "vulnerable": True,
                    "criteria": "cpe:2.3:a:nginx:nginx:1.26.2:*:*:*:*:*:*:*",
                }]
            }]
        }]
    }
    assert not _cve_matches_cpe_version(cve, "OpenSSH", "1.26.2")


def test_guardian_cpe_recurses_into_children():
    cve = {
        "configurations": [{
            "nodes": [{
                "operator": "OR",
                "children": [{
                    "cpeMatch": [{
                        "vulnerable": True,
                        "criteria": "cpe:2.3:a:openbsd:openssh:9.6p1:*:*:*:*:*:*:*",
                    }]
                }]
            }]
        }]
    }
    assert _cve_matches_cpe_version(cve, "OpenSSH", "9.6p1")


def test_guardian_cpe_missing_configuration_is_rejected():
    assert not _cve_matches_cpe_version(
        {"id": "CVE-2099-0001"}, "OpenSSH", "10.2p1"
    )



def test_guardian_cpe_and_requires_all_conditions():
    cve = {
        "configurations": [{
            "nodes": [{
                "operator": "AND",
                "cpeMatch": [{
                    "vulnerable": True,
                    "criteria": "cpe:2.3:a:openbsd:openssh:9.6p1:*:*:*:*:*:*:*",
                }, {
                    "vulnerable": False,
                    "criteria": "cpe:2.3:o:canonical:ubuntu_linux:22.04:*:*:*:*:*:*:*",
                }],
            }]
        }]
    }
    # Unknown OS conditions retain a potential match, not a confirmed vulnerability.
    assert _cve_matches_cpe_version(cve, "OpenSSH", "9.6p1")



def test_guardian_cpe_or_accepts_matching_branch():
    cve = {
        "configurations": [{
            "nodes": [{
                "operator": "OR",
                "cpeMatch": [{
                    "vulnerable": True,
                    "criteria": "cpe:2.3:a:openbsd:openssh:9.6p1:*:*:*:*:*:*:*",
                }, {
                    "vulnerable": True,
                    "criteria": "cpe:2.3:a:nginx:nginx:1.26.2:*:*:*:*:*:*:*",
                }],
            }]
        }]
    }
    assert _cve_matches_cpe_version(cve, "OpenSSH", "9.6p1")


def test_guardian_cpe_negated_node_is_not_confirmed():
    cve = {
        "configurations": [{
            "nodes": [{
                "operator": "OR",
                "negate": True,
                "cpeMatch": [{
                    "vulnerable": True,
                    "criteria": "cpe:2.3:a:openbsd:openssh:9.6p1:*:*:*:*:*:*:*",
                }],
            }]
        }]
    }
    assert not _cve_matches_cpe_version(cve, "OpenSSH", "9.6p1")


def test_guardian_cpe_unknown_version_only_matches_unrestricted_product():
    unrestricted = {
        "configurations": [{
            "nodes": [{
                "cpeMatch": [{
                    "vulnerable": True,
                    "criteria": "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*",
                }]
            }]
        }]
    }
    version_limited = {
        "configurations": [{
            "nodes": [{
                "cpeMatch": [{
                    "vulnerable": True,
                    "criteria": "cpe:2.3:a:openbsd:openssh:9.6p1:*:*:*:*:*:*:*",
                }]
            }]
        }]
    }
    assert _cve_matches_cpe_version(unrestricted, "OpenSSH", "Unknown")
    assert not _cve_matches_cpe_version(version_limited, "OpenSSH", "Unknown")


def test_guardian_cpe_rejects_partial_product_name_match():
    cve = {
        "configurations": [{
            "nodes": [{
                "cpeMatch": [{
                    "vulnerable": True,
                    "criteria": "cpe:2.3:a:vendor:nginx:1.26.2:*:*:*:*:*:*:*",
                }]
            }]
        }]
    }
    assert not _cve_matches_cpe_version(cve, "nginx-proxy", "1.26.2")


def test_guardian_cpe_matches_generic_vendor_plus_product_name():
    cve = {
        "configurations": [{
            "nodes": [{
                "cpeMatch": [{
                    "vulnerable": True,
                    "criteria": "cpe:2.3:a:apache:http_server:2.4.9:*:*:*:*:*:*:*",
                }]
            }]
        }]
    }
    assert _cve_matches_cpe_version(cve, "Apache HTTP Server", "2.4.9")
    assert not _cve_matches_cpe_version(cve, "Apache HTTP Proxy", "2.4.9")
