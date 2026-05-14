from rules import (
	HorizontalScanRule,
	IcmpFloodRule,
	LargeIcmpRule,
	MultiTargetScanRule,
	PortScanRule,
	SynAckImbalanceRule,
	SynFloodRule,
	TcpFlagAnomalyRule,
	UdpFloodRule,
)


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


def test_udp_flood_rule_triggers():
	rule = UdpFloodRule(threshold=5, window_seconds=1.0)
	alert = None
	for idx in range(3):
		packet = make_packet(
			protocol="UDP",
			timestamp=1000.0 + (idx * 0.1),
			packet_count=2,
		)
		alert = rule.check(packet)
	assert alert is not None
	assert alert["rule"] == "udp_flood"


def test_icmp_flood_rule_triggers():
	rule = IcmpFloodRule(threshold=3, window_seconds=1.0)
	alert = None
	for idx in range(2):
		packet = make_packet(
			protocol="ICMP",
			timestamp=1000.0 + (idx * 0.2),
			packet_count=2,
		)
		alert = rule.check(packet)
	assert alert is not None
	assert alert["rule"] == "icmp_flood"


def test_horizontal_scan_rule_triggers():
	rule = HorizontalScanRule(threshold=3, window_seconds=5.0)
	alert = None
	for idx, host in enumerate(["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"]):
		packet = make_packet(
			timestamp=1000.0 + (idx * 0.2),
			dst_ip=host,
			dst_port=445,
		)
		alert = rule.check(packet)
	assert alert is not None
	assert alert["rule"] == "horizontal_scan"


def test_multi_target_scan_rule_triggers():
	rule = MultiTargetScanRule(threshold=3, window_seconds=5.0)
	alert = None
	for idx, host in enumerate(["10.0.0.10", "10.0.0.11", "10.0.0.12", "10.0.0.13"]):
		packet = make_packet(
			timestamp=1000.0 + (idx * 0.2),
			dst_ip=host,
			dst_port=80 + idx,
		)
		alert = rule.check(packet)
	assert alert is not None
	assert alert["rule"] == "multi_target_scan"


def test_syn_ack_imbalance_rule_triggers():
	rule = SynAckImbalanceRule(threshold_syn=5, window_seconds=5.0, ratio_threshold=0.2)
	packet = make_packet(timestamp=1000.0, syn_count=6, ack_count=0)
	alert = rule.check(packet)
	assert alert is not None
	assert alert["rule"] == "syn_ack_imbalance"


def test_tcp_flag_anomaly_rule_triggers():
	rule = TcpFlagAnomalyRule()
	packet = make_packet(tcp_flags="FPU")
	alert = rule.check(packet)
	assert alert is not None
	assert alert["rule"] == "tcp_flag_anomaly"
