import pytest
import socket
from scanner import validate_target_safety, pin_dns_resolution
from database import get_latest_domain_status, init_db

init_db()

def test_ssrf_blocks_loopback():
    is_safe, ip, msg = validate_target_safety("http://127.0.0.1/index.php")
    assert is_safe is False
    assert "restricted" in ip.lower() or "prohibited" in ip.lower()

def test_ssrf_blocks_localhost():
    is_safe, ip, msg = validate_target_safety("http://localhost:8000")
    assert is_safe is False
    assert "prohibited" in ip.lower()

def test_ssrf_blocks_aws_metadata():
    is_safe, ip, msg = validate_target_safety("http://169.254.169.254/latest/meta-data/")
    assert is_safe is False
    assert "restricted" in ip.lower()

def test_ssrf_blocks_private_lan():
    is_safe, ip, msg = validate_target_safety("http://192.168.1.1/admin")
    assert is_safe is False
    assert "restricted" in ip.lower()

def test_dns_pinning_context_isolation():
    with pin_dns_resolution("example.com", "93.184.216.34"):
        res = socket.getaddrinfo("example.com", 80)
        assert res[0][4][0] == "93.184.216.34"

def test_badge_status_unverified():
    status = get_latest_domain_status("random-unscanned-domain-xyz.com")
    assert status == "unverified"
