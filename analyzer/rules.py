from collections import deque
from typing import Deque, Dict, List, Optional, Tuple


class BaseRule:
	name = "base"
	severity = "info"
	description = ""

	def check(self, packet: dict) -> Optional[dict]:
		raise NotImplementedError

	def _build_alert(self, packet: dict, message: str, metadata: Optional[dict] = None) -> dict:
		return {
			"timestamp": packet.get("timestamp"),
			"rule": self.name,
			"severity": self.severity,
			"message": message,
			"src_ip": packet.get("src_ip"),
			"dst_ip": packet.get("dst_ip"),
			"src_port": packet.get("src_port"),
			"dst_port": packet.get("dst_port"),
			"metadata": metadata or {},
		}


class SynFloodRule(BaseRule):
	name = "syn_flood"
	severity = "high"
	description = "More than 50 SYN packets in 1 second from the same IP"

	def __init__(self, threshold: int = 50, window_seconds: float = 1.0, state_ttl: float = 10.0) -> None:
		self.threshold = threshold
		self.window_seconds = window_seconds
		self.state_ttl = state_ttl
		self.syn_events: Dict[str, Deque[Tuple[float, int]]] = {}
		self.last_seen: Dict[str, float] = {}
		self.last_alert: Dict[str, float] = {}

	def check(self, packet: dict) -> Optional[dict]:
		if packet.get("protocol") != "TCP":
			return None

		flags = packet.get("tcp_flags") or ""
		src_ip = packet.get("src_ip")
		timestamp = float(packet.get("timestamp", 0))
		if not src_ip or not timestamp:
			return None

		syn_count = int(packet.get("syn_count") or 0)
		if syn_count <= 0:
			if "S" not in flags or "A" in flags:
				return None
			syn_count = 1

		events = self.syn_events.setdefault(src_ip, deque())
		events.append((timestamp, syn_count))
		self.last_seen[src_ip] = timestamp

		cutoff = timestamp - self.window_seconds
		while events and events[0][0] < cutoff:
			events.popleft()

		self._cleanup(timestamp)

		total_syn = sum(count for _, count in events)
		if total_syn > self.threshold:
			last_alert_time = self.last_alert.get(src_ip, 0)
			if timestamp - last_alert_time >= self.window_seconds:
				self.last_alert[src_ip] = timestamp
				message = (
					f"Possible SYN flood: {total_syn} SYN packets in {self.window_seconds}s"
				)
				return self._build_alert(packet, message, {"syn_count": total_syn})

		return None

	def _cleanup(self, now: float) -> None:
		expire = now - self.state_ttl
		stale = [ip for ip, last in self.last_seen.items() if last < expire]
		for ip in stale:
			self.last_seen.pop(ip, None)
			self.syn_events.pop(ip, None)
			self.last_alert.pop(ip, None)


class PortScanRule(BaseRule):
	name = "port_scan"
	severity = "medium"
	description = "More than 20 distinct destination ports in 5 seconds"

	def __init__(self, threshold: int = 20, window_seconds: float = 5.0, state_ttl: float = 10.0) -> None:
		self.threshold = threshold
		self.window_seconds = window_seconds
		self.state_ttl = state_ttl
		self.attempts: Dict[str, Deque[Tuple[float, int]]] = {}
		self.last_seen: Dict[str, float] = {}
		self.last_alert: Dict[str, float] = {}

	def check(self, packet: dict) -> Optional[dict]:
		if packet.get("protocol") not in {"TCP", "UDP"}:
			return None

		src_ip = packet.get("src_ip")
		dst_port = packet.get("dst_port")
		timestamp = float(packet.get("timestamp", 0))
		if not src_ip or not dst_port or not timestamp:
			return None

		events = self.attempts.setdefault(src_ip, deque())
		events.append((timestamp, int(dst_port)))
		self.last_seen[src_ip] = timestamp

		cutoff = timestamp - self.window_seconds
		while events and events[0][0] < cutoff:
			events.popleft()

		self._cleanup(timestamp)

		ports = {port for _, port in events}
		if len(ports) > self.threshold:
			last_alert_time = self.last_alert.get(src_ip, 0)
			if timestamp - last_alert_time >= self.window_seconds:
				self.last_alert[src_ip] = timestamp
				message = f"Possible port scan: {len(ports)} ports in {self.window_seconds}s"
				return self._build_alert(packet, message, {"port_count": len(ports)})

		return None

	def _cleanup(self, now: float) -> None:
		expire = now - self.state_ttl
		stale = [ip for ip, last in self.last_seen.items() if last < expire]
		for ip in stale:
			self.last_seen.pop(ip, None)
			self.attempts.pop(ip, None)
			self.last_alert.pop(ip, None)


class LargeIcmpRule(BaseRule):
	name = "large_icmp"
	severity = "low"
	description = "ICMP payload larger than 1000 bytes"

	def __init__(self, threshold: int = 1000) -> None:
		self.threshold = threshold

	def check(self, packet: dict) -> Optional[dict]:
		if packet.get("protocol") != "ICMP":
			return None

		payload_size = int(packet.get("payload_size", 0))
		if payload_size > self.threshold:
			message = f"Large ICMP payload: {payload_size} bytes"
			return self._build_alert(packet, message, {"payload_size": payload_size})

		return None


class RuleEngine:
	def __init__(self, rules: Optional[List[BaseRule]] = None) -> None:
		self.rules = rules or [SynFloodRule(), PortScanRule(), LargeIcmpRule()]

	def process_packet(self, packet: dict) -> List[dict]:
		alerts: List[dict] = []
		for rule in self.rules:
			alert = rule.check(packet)
			if alert:
				alerts.append(alert)
		return alerts
