import importlib
import sys

import pytest
from scapy.all import Ether, IP, IPv6, TCP, UDP, Raw


def api():
    # Missing contract is an explicit assertion during the first RED run.
    from backend import packet_capture
    assert hasattr(packet_capture, "packet_metadata"), "capture must expose an import-safe parser"
    from backend.flows import FlowBuilder, features
    return packet_capture.packet_metadata, FlowBuilder, features


def packet(t=1, reverse=False, ipv6=False):
    src, dst = ("2001:db8::1", "2001:db8::2") if ipv6 else ("192.0.2.1", "198.51.100.2")
    a, b = (dst, src) if reverse else (src, dst)
    p = Ether() / (IPv6(src=a, dst=b) if ipv6 else IP(src=a, dst=b)) / TCP(sport=80 if reverse else 1234, dport=1234 if reverse else 80, flags="A") / Raw(b"abcd")
    p.time = t
    return p


def test_capture_module_has_no_import_side_effects(monkeypatch):
    import scapy.all
    def forbidden(*args, **kwargs):
        pytest.fail("import must not start capture")
    monkeypatch.setattr(scapy.all, "sniff", forbidden)
    sys.modules.pop("backend.packet_capture", None)
    importlib.import_module("backend.packet_capture")


def test_direction_length_and_time_units():
    parse, Builder, features = api()
    b = Builder()
    b.add(parse(packet(1)))
    b.add(parse(packet(1.5, reverse=True)))
    f = b.flush(2, force=True)[0]
    x = features(f)
    assert x["duration_s"] == .5
    assert x["fwd_packets"] == x["bwd_packets"] == 1
    assert x["fwd_bytes"] == x["bwd_bytes"] == 44
    assert x["ack_count"] == 2
    assert x["iat_mean_s"] == .5


def test_timeout_splits_and_reverse_orientation_is_stable():
    parse, Builder, _ = api()
    b = Builder(idle_timeout=2, active_timeout=10)
    assert b.add(parse(packet(1))) == []
    assert b.add(parse(packet(2, reverse=True))) == []
    old = b.add(parse(packet(5)))
    assert len(old) == 1 and len(old[0].packets) == 2
    assert len(b.flush(8)) == 1


def test_ipv6_and_unsupported_packets():
    parse, _, _ = api()
    assert parse(packet(ipv6=True)).ip_version == 6
    assert parse(Ether()/Raw(b"x")) is None
    assert parse(IP()/Raw(b"x")) is None
    p = IP()/UDP(sport=12,dport=53)
    p.time = float("nan")
    assert parse(p) is None


def test_out_of_order_is_counted_and_never_negative():
    parse, Builder, features = api()
    b = Builder()
    b.add(parse(packet(2)))
    b.add(parse(packet(1)))
    f = b.flush(3, force=True)[0]
    assert b.out_of_order == 1
    assert features(f)["duration_s"] == 1


def test_capacity_is_bounded_and_fin_closes_flow():
    parse, Builder, _ = api()
    b = Builder(max_flows=1)
    b.add(parse(packet()))
    p = packet(2); p[TCP].sport = 5678
    assert len(b.add(parse(p))) == 1
    assert b.evicted == 1
    p = packet(3); p[TCP].sport=5678; p[TCP].flags="R"
    assert len(b.add(parse(p))) == 1
    assert not b.flows


def test_quoted_tcp_inside_icmp_is_not_a_transport_flow():
    from scapy.all import ICMP
    parse,_,_=api()
    quoted=IP(src='192.0.2.1',dst='198.51.100.2')/ICMP(type=3)/IP()/TCP()
    assert parse(quoted) is None

def test_ipv6_quoted_ipv4_transport_is_not_a_flow():
    from scapy.layers.inet6 import ICMPv6DestUnreach
    parse,_,_=api()
    assert parse(IPv6()/ICMPv6DestUnreach()/IP()/UDP()) is None
