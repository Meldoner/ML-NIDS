import logging
import os
import signal
import threading
import time
from collections import deque
from typing import Any, Deque, Dict, Optional, Tuple

import requests
from scapy.all import AsyncSniffer, ICMP, IP, TCP, UDP


BACKEND_URL = os.getenv("BACKEND_URL", "http://127.0.0.1:8000/api/v1/traffic")
BATCH_INTERVAL = float(os.getenv("BATCH_INTERVAL", "1.5"))
BATCH_MAX_SIZE = int(os.getenv("BATCH_MAX_SIZE", "500"))
MAX_BUFFER_SIZE = int(os.getenv("MAX_BUFFER_SIZE", "5000"))
SNIFF_INTERFACE = os.getenv("SNIFF_INTERFACE")
BPF_FILTER = os.getenv("BPF_FILTER", "ip")
CONNECT_TIMEOUT = float(os.getenv("CONNECT_TIMEOUT", "3"))
READ_TIMEOUT = float(os.getenv("READ_TIMEOUT", "5"))
BACKEND_API_KEY = os.getenv("BACKEND_API_KEY")
API_KEY_HEADER = os.getenv("API_KEY_HEADER", "X-API-Key")


buffer: Deque[Dict[str, Any]] = deque()
buffer_lock = threading.Lock()
flush_event = threading.Event()
stop_event = threading.Event()
flows: Dict[Tuple[str, str, Optional[int], Optional[int], str], Dict[str, Any]] = {}
flows_lock = threading.Lock()


def _get_payload_size(packet) -> int:
	if ICMP in packet:
		return len(bytes(packet[ICMP].payload))
	if TCP in packet:
		return len(bytes(packet[TCP].payload))
	if UDP in packet:
		return len(bytes(packet[UDP].payload))
	return 0


def _packet_to_dict(packet) -> Optional[Dict[str, Any]]:
	if IP not in packet:
		return None

	ip_layer = packet[IP]
	protocol = "OTHER"
	tcp_flags = None
	src_port = None
	dst_port = None

	if TCP in packet:
		protocol = "TCP"
		tcp_flags = str(packet[TCP].flags)
		src_port = int(packet[TCP].sport)
		dst_port = int(packet[TCP].dport)
	elif UDP in packet:
		protocol = "UDP"
		src_port = int(packet[UDP].sport)
		dst_port = int(packet[UDP].dport)
	elif ICMP in packet:
		protocol = "ICMP"

	payload_size = _get_payload_size(packet)

	return {
		"timestamp": float(getattr(packet, "time", time.time())),
		"src_ip": ip_layer.src,
		"dst_ip": ip_layer.dst,
		"src_port": src_port,
		"dst_port": dst_port,
		"protocol": protocol,
		"tcp_flags": tcp_flags,
		"payload_size": payload_size,
	}


def _update_flow(data: Dict[str, Any]) -> None:
	key = (
		data["src_ip"],
		data["dst_ip"],
		data.get("src_port"),
		data.get("dst_port"),
		data.get("protocol", "OTHER"),
	)

	timestamp = float(data.get("timestamp", 0))
	payload_size = int(data.get("payload_size", 0))
	tcp_flags = data.get("tcp_flags") or ""

	with flows_lock:
		stats = flows.get(key)
		if not stats:
			stats = {
				"first_seen": timestamp,
				"last_seen": timestamp,
				"packet_count": 0,
				"payload_bytes": 0,
				"max_payload_size": 0,
				"syn_count": 0,
				"ack_count": 0,
				"tcp_flags": set(),
			}
			flows[key] = stats

		stats["packet_count"] += 1
		stats["payload_bytes"] += payload_size
		stats["max_payload_size"] = max(stats["max_payload_size"], payload_size)
		stats["last_seen"] = timestamp
		if tcp_flags:
			stats["tcp_flags"].update(tcp_flags)
		if data.get("protocol") == "TCP":
			if "S" in tcp_flags and "A" not in tcp_flags:
				stats["syn_count"] += 1
			if "A" in tcp_flags:
				stats["ack_count"] += 1

		if len(flows) >= BATCH_MAX_SIZE:
			flush_event.set()


def _drain_flows() -> list[Dict[str, Any]]:
	with flows_lock:
		if not flows:
			return []
		items = list(flows.items())
		flows.clear()

	records: list[Dict[str, Any]] = []
	for key, stats in items:
		src_ip, dst_ip, src_port, dst_port, protocol = key
		flags = "".join(sorted(stats["tcp_flags"])) if stats["tcp_flags"] else None
		records.append(
			{
				"timestamp": stats["last_seen"],
				"first_seen": stats["first_seen"],
				"last_seen": stats["last_seen"],
				"src_ip": src_ip,
				"dst_ip": dst_ip,
				"src_port": src_port,
				"dst_port": dst_port,
				"protocol": protocol,
				"tcp_flags": flags,
				"payload_size": stats["max_payload_size"],
				"payload_bytes": stats["payload_bytes"],
				"packet_count": stats["packet_count"],
				"syn_count": stats["syn_count"],
				"ack_count": stats["ack_count"],
			}
		)

	return records


def _enqueue_packet(packet) -> None:
	data = _packet_to_dict(packet)
	if not data:
		return

	_update_flow(data)


def _send_batch(session: requests.Session, batch: list[Dict[str, Any]]) -> bool:
	try:
		headers = {API_KEY_HEADER: BACKEND_API_KEY} if BACKEND_API_KEY else None
		response = session.post(
			BACKEND_URL,
			json={"packets": batch},
			headers=headers,
			timeout=(CONNECT_TIMEOUT, READ_TIMEOUT),
		)
		if response.status_code >= 400:
			logging.warning("Backend error %s: %s", response.status_code, response.text)
			return False
		return True
	except requests.RequestException as exc:
		logging.warning("Failed to send batch: %s", exc)
		return False


def _sender_loop() -> None:
	session = requests.Session()
	while not stop_event.is_set():
		flush_event.wait(BATCH_INTERVAL)
		flush_event.clear()

		if stop_event.is_set():
			break

		new_records = _drain_flows()
		if new_records:
			with buffer_lock:
				for record in new_records:
					if len(buffer) >= MAX_BUFFER_SIZE:
						buffer.popleft()
					buffer.append(record)

		with buffer_lock:
			if not buffer:
				continue
			batch: list[Dict[str, Any]] = []
			while buffer and len(batch) < BATCH_MAX_SIZE:
				batch.append(buffer.popleft())

		if not _send_batch(session, batch):
			with buffer_lock:
				available = MAX_BUFFER_SIZE - len(buffer)
				if available > 0:
					replay = batch[:available]
					buffer.extendleft(reversed(replay))
				else:
					logging.warning("Dropping %s packets due to full buffer", len(batch))


def _handle_signal(signum, frame) -> None:
	logging.info("Received signal %s, stopping...", signum)
	stop_event.set()
	flush_event.set()


def main() -> None:
	logging.basicConfig(
		level=logging.INFO,
		format="%(asctime)s [%(levelname)s] %(message)s",
	)

	signal.signal(signal.SIGINT, _handle_signal)
	signal.signal(signal.SIGTERM, _handle_signal)

	sender_thread = threading.Thread(target=_sender_loop, name="batch-sender")
	sender_thread.start()

	sniffer = AsyncSniffer(
		iface=SNIFF_INTERFACE,
		filter=BPF_FILTER,
		prn=_enqueue_packet,
		store=False,
	)
	sniffer.start()

	logging.info("Sniffer started (interface=%s, filter=%s)", SNIFF_INTERFACE, BPF_FILTER)

	try:
		while not stop_event.is_set():
			time.sleep(0.5)
	finally:
		sniffer.stop()
		stop_event.set()
		flush_event.set()
		sender_thread.join(timeout=5)
		logging.info("Sniffer stopped")


if __name__ == "__main__":
	main()
