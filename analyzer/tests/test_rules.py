from rules import LargeIcmpRule, PortScanRule, SynFloodRule


def make_packet(**overrides):
	data = {
		"timestamp": 1000.0,
		"src_ip": "10.0.0.10",
		"dst_ip": "10.0.0.20",
		"src_port": 12345,
		"dst_port": 80,
		"protocol": "TCP",
		"tcp_flags": "S",
		"payload_size": 0,
	}
	data.update(overrides)
	return data


def test_syn_flood_rule_triggers_on_threshold():
	rule = SynFloodRule(threshold=3, window_seconds=1.0)
	alert = None
	for idx in range(4):
		packet = make_packet(timestamp=1000.0 + (idx * 0.1), tcp_flags="S")
		alert = rule.check(packet)
	assert alert is not None
	assert alert["rule"] == "syn_flood"


def test_syn_flood_rule_uses_syn_count():
	rule = SynFloodRule(threshold=5, window_seconds=1.0)
	packet = make_packet(timestamp=1001.0, syn_count=6)
	alert = rule.check(packet)
	assert alert is not None
	assert alert["rule"] == "syn_flood"


def test_port_scan_rule_triggers_on_distinct_ports():
	rule = PortScanRule(threshold=3, window_seconds=5.0)
	alert = None
	for port in [21, 22, 23, 24]:
		packet = make_packet(timestamp=1000.0 + (port / 1000), dst_port=port)
		alert = rule.check(packet)
	assert alert is not None
	assert alert["rule"] == "port_scan"


def test_large_icmp_rule_triggers():
	rule = LargeIcmpRule(threshold=1000)
	packet = make_packet(protocol="ICMP", payload_size=1201)
	alert = rule.check(packet)
	assert alert is not None
	assert alert["rule"] == "large_icmp"
