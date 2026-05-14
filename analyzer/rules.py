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


class UdpFloodRule(BaseRule):
	name = "udp_flood"
	severity = "medium"
	description = "High UDP packet rate from the same IP"

	def __init__(self, threshold: int = 200, window_seconds: float = 1.0, state_ttl: float = 10.0) -> None:
		self.threshold = threshold
		self.window_seconds = window_seconds
		self.state_ttl = state_ttl
		self.events: Dict[str, Deque[Tuple[float, int]]] = {}
		self.last_seen: Dict[str, float] = {}
		self.last_alert: Dict[str, float] = {}

	def check(self, packet: dict) -> Optional[dict]:
		if packet.get("protocol") != "UDP":
			return None

		src_ip = packet.get("src_ip")
		timestamp = float(packet.get("timestamp", 0))
		if not src_ip or not timestamp:
			return None

		count = int(packet.get("packet_count") or 1)
		events = self.events.setdefault(src_ip, deque())
		events.append((timestamp, count))
		self.last_seen[src_ip] = timestamp

		cutoff = timestamp - self.window_seconds
		while events and events[0][0] < cutoff:
			events.popleft()

		self._cleanup(timestamp)

		total = sum(value for _, value in events)
		if total > self.threshold:
			last_alert_time = self.last_alert.get(src_ip, 0)
			if timestamp - last_alert_time >= self.window_seconds:
				self.last_alert[src_ip] = timestamp
				message = f"Possible UDP flood: {total} packets in {self.window_seconds}s"
				return self._build_alert(packet, message, {"packet_count": total})

		return None

	def _cleanup(self, now: float) -> None:
		expire = now - self.state_ttl
		stale = [ip for ip, last in self.last_seen.items() if last < expire]
		for ip in stale:
			self.last_seen.pop(ip, None)
			self.events.pop(ip, None)
			self.last_alert.pop(ip, None)


class IcmpFloodRule(BaseRule):
	name = "icmp_flood"
	severity = "medium"
	description = "High ICMP packet rate from the same IP"

	def __init__(self, threshold: int = 100, window_seconds: float = 1.0, state_ttl: float = 10.0) -> None:
		self.threshold = threshold
		self.window_seconds = window_seconds
		self.state_ttl = state_ttl
		self.events: Dict[str, Deque[Tuple[float, int]]] = {}
		self.last_seen: Dict[str, float] = {}
		self.last_alert: Dict[str, float] = {}

	def check(self, packet: dict) -> Optional[dict]:
		if packet.get("protocol") != "ICMP":
			return None

		src_ip = packet.get("src_ip")
		timestamp = float(packet.get("timestamp", 0))
		if not src_ip or not timestamp:
			return None

		count = int(packet.get("packet_count") or 1)
		events = self.events.setdefault(src_ip, deque())
		events.append((timestamp, count))
		self.last_seen[src_ip] = timestamp

		cutoff = timestamp - self.window_seconds
		while events and events[0][0] < cutoff:
			events.popleft()

		self._cleanup(timestamp)

		total = sum(value for _, value in events)
		if total > self.threshold:
			last_alert_time = self.last_alert.get(src_ip, 0)
			if timestamp - last_alert_time >= self.window_seconds:
				self.last_alert[src_ip] = timestamp
				message = f"Possible ICMP flood: {total} packets in {self.window_seconds}s"
				return self._build_alert(packet, message, {"packet_count": total})

		return None

	def _cleanup(self, now: float) -> None:
		expire = now - self.state_ttl
		stale = [ip for ip, last in self.last_seen.items() if last < expire]
		for ip in stale:
			self.last_seen.pop(ip, None)
			self.events.pop(ip, None)
			self.last_alert.pop(ip, None)


class HorizontalScanRule(BaseRule):
	name = "horizontal_scan"
	severity = "medium"
	description = "Many destination hosts on the same port within a short window"

	def __init__(self, threshold: int = 20, window_seconds: float = 5.0, state_ttl: float = 10.0) -> None:
		self.threshold = threshold
		self.window_seconds = window_seconds
		self.state_ttl = state_ttl
		self.events: Dict[Tuple[str, int], Deque[Tuple[float, str]]] = {}
		self.last_seen: Dict[Tuple[str, int], float] = {}
		self.last_alert: Dict[Tuple[str, int], float] = {}

	def check(self, packet: dict) -> Optional[dict]:
		if packet.get("protocol") not in {"TCP", "UDP"}:
			return None

		src_ip = packet.get("src_ip")
		dst_ip = packet.get("dst_ip")
		dst_port = packet.get("dst_port")
		timestamp = float(packet.get("timestamp", 0))
		if not src_ip or not dst_ip or not dst_port or not timestamp:
			return None

		key = (src_ip, int(dst_port))
		events = self.events.setdefault(key, deque())
		events.append((timestamp, dst_ip))
		self.last_seen[key] = timestamp

		cutoff = timestamp - self.window_seconds
		while events and events[0][0] < cutoff:
			events.popleft()

		self._cleanup(timestamp)

		hosts = {host for _, host in events}
		if len(hosts) > self.threshold:
			last_alert_time = self.last_alert.get(key, 0)
			if timestamp - last_alert_time >= self.window_seconds:
				self.last_alert[key] = timestamp
				message = (
					f"Possible horizontal scan: {len(hosts)} hosts on port {dst_port}"
				)
				return self._build_alert(packet, message, {"host_count": len(hosts)})

		return None

	def _cleanup(self, now: float) -> None:
		expire = now - self.state_ttl
		stale = [key for key, last in self.last_seen.items() if last < expire]
		for key in stale:
			self.last_seen.pop(key, None)
			self.events.pop(key, None)
			self.last_alert.pop(key, None)


class MultiTargetScanRule(BaseRule):
	name = "multi_target_scan"
	severity = "medium"
	description = "Many destination hosts within a short window"

	def __init__(self, threshold: int = 30, window_seconds: float = 5.0, state_ttl: float = 10.0) -> None:
		self.threshold = threshold
		self.window_seconds = window_seconds
		self.state_ttl = state_ttl
		self.events: Dict[str, Deque[Tuple[float, str]]] = {}
		self.last_seen: Dict[str, float] = {}
		self.last_alert: Dict[str, float] = {}

	def check(self, packet: dict) -> Optional[dict]:
		if packet.get("protocol") not in {"TCP", "UDP"}:
			return None

		src_ip = packet.get("src_ip")
		dst_ip = packet.get("dst_ip")
		timestamp = float(packet.get("timestamp", 0))
		if not src_ip or not dst_ip or not timestamp:
			return None

		events = self.events.setdefault(src_ip, deque())
		events.append((timestamp, dst_ip))
		self.last_seen[src_ip] = timestamp

		cutoff = timestamp - self.window_seconds
		while events and events[0][0] < cutoff:
			events.popleft()

		self._cleanup(timestamp)

		hosts = {host for _, host in events}
		if len(hosts) > self.threshold:
			last_alert_time = self.last_alert.get(src_ip, 0)
			if timestamp - last_alert_time >= self.window_seconds:
				self.last_alert[src_ip] = timestamp
				message = f"Possible multi-target scan: {len(hosts)} hosts"
				return self._build_alert(packet, message, {"host_count": len(hosts)})

		return None

	def _cleanup(self, now: float) -> None:
		expire = now - self.state_ttl
		stale = [ip for ip, last in self.last_seen.items() if last < expire]
		for ip in stale:
			self.last_seen.pop(ip, None)
			self.events.pop(ip, None)
			self.last_alert.pop(ip, None)


class SynAckImbalanceRule(BaseRule):
	name = "syn_ack_imbalance"
	severity = "high"
	description = "High SYN count with low ACK ratio"

	def __init__(
		self,
		threshold_syn: int = 50,
		window_seconds: float = 5.0,
		ratio_threshold: float = 0.2,
		state_ttl: float = 10.0,
	) -> None:
		self.threshold_syn = threshold_syn
		self.window_seconds = window_seconds
		self.ratio_threshold = ratio_threshold
		self.state_ttl = state_ttl
		self.events: Dict[str, Deque[Tuple[float, int, int]]] = {}
		self.last_seen: Dict[str, float] = {}
		self.last_alert: Dict[str, float] = {}

	def check(self, packet: dict) -> Optional[dict]:
		if packet.get("protocol") != "TCP":
			return None

		src_ip = packet.get("src_ip")
		timestamp = float(packet.get("timestamp", 0))
		if not src_ip or not timestamp:
			return None

		syn_count = int(packet.get("syn_count") or 0)
		ack_count = int(packet.get("ack_count") or 0)
		flags = packet.get("tcp_flags") or ""
		if syn_count == 0 and "S" in flags and "A" not in flags:
			syn_count = 1
		if ack_count == 0 and "A" in flags:
			ack_count = 1

		events = self.events.setdefault(src_ip, deque())
		events.append((timestamp, syn_count, ack_count))
		self.last_seen[src_ip] = timestamp

		cutoff = timestamp - self.window_seconds
		while events and events[0][0] < cutoff:
			events.popleft()

		self._cleanup(timestamp)

		total_syn = sum(value for _, value, _ in events)
		total_ack = sum(value for _, _, value in events)
		if total_syn >= self.threshold_syn:
			ratio = (total_ack / total_syn) if total_syn else 1.0
			if ratio <= self.ratio_threshold:
				last_alert_time = self.last_alert.get(src_ip, 0)
				if timestamp - last_alert_time >= self.window_seconds:
					self.last_alert[src_ip] = timestamp
					message = (
						f"SYN/ACK imbalance: {total_syn} SYN, {total_ack} ACK"
					)
					return self._build_alert(
						packet,
						message,
						{"syn_count": total_syn, "ack_count": total_ack, "ack_ratio": ratio},
					)

		return None

	def _cleanup(self, now: float) -> None:
		expire = now - self.state_ttl
		stale = [ip for ip, last in self.last_seen.items() if last < expire]
		for ip in stale:
			self.last_seen.pop(ip, None)
			self.events.pop(ip, None)
			self.last_alert.pop(ip, None)


class TcpFlagAnomalyRule(BaseRule):
	name = "tcp_flag_anomaly"
	severity = "medium"
	description = "Suspicious TCP flag combinations"

	def check(self, packet: dict) -> Optional[dict]:
		if packet.get("protocol") != "TCP":
			return None

		flags_raw = packet.get("tcp_flags")
		if not flags_raw:
			message = "Possible NULL scan: no TCP flags"
			return self._build_alert(packet, message, {"flags": ""})

		flags = set(str(flags_raw))
		if flags == {"F"}:
			message = "Possible FIN scan"
			return self._build_alert(packet, message, {"flags": "F"})

		if {"F", "P", "U"}.issubset(flags) and flags.isdisjoint({"S", "A", "R"}):
			message = "Possible XMAS scan"
			return self._build_alert(packet, message, {"flags": "".join(sorted(flags))})

		return None


class RuleEngine:
	def __init__(self, rules: Optional[List[BaseRule]] = None) -> None:
		self.rules = rules or [
			SynFloodRule(),
			SynAckImbalanceRule(),
			PortScanRule(),
			HorizontalScanRule(),
			MultiTargetScanRule(),
			UdpFloodRule(),
			IcmpFloodRule(),
			LargeIcmpRule(),
			TcpFlagAnomalyRule(),
		]

	def process_packet(self, packet: dict) -> List[dict]:
		alerts: List[dict] = []
		for rule in self.rules:
			alert = rule.check(packet)
			if alert:
				alerts.append(alert)
		return alerts
