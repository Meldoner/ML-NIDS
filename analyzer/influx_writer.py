import logging
import os
from datetime import datetime, timezone
from typing import Any, Iterable, Optional

from influxdb_client import InfluxDBClient, Point, WriteOptions


class InfluxDBWriter:
	def __init__(self) -> None:
		self.url = os.getenv("INFLUXDB_URL", "http://localhost:8086")
		self.token = os.getenv("INFLUXDB_TOKEN")
		self.org = os.getenv("INFLUXDB_ORG")
		self.bucket = os.getenv("INFLUXDB_BUCKET")
		self.write_traffic_enabled = os.getenv("INFLUX_WRITE_TRAFFIC", "1") == "1"

		if not all([self.token, self.org, self.bucket]):
			logging.warning("InfluxDB is not fully configured; writes are disabled")
			self.enabled = False
			self.client = None
			self.write_api = None
			return

		self.enabled = True
		self.client = InfluxDBClient(url=self.url, token=self.token, org=self.org)
		self.write_api = self.client.write_api(
			write_options=WriteOptions(batch_size=500, flush_interval=1000)
		)

	def _to_dict(self, item: Any) -> dict:
		if hasattr(item, "model_dump"):
			return item.model_dump()
		if isinstance(item, dict):
			return item
		raise TypeError("Unsupported payload type for InfluxDB writer")

	def _to_time(self, timestamp: float) -> datetime:
		return datetime.fromtimestamp(timestamp, tz=timezone.utc)

	def write_alerts(self, alerts: Iterable[Any]) -> None:
		if not self.enabled:
			return

		points: list[Point] = []
		for alert in alerts:
			data = self._to_dict(alert)
			point = (
				Point("alerts")
				.tag("rule", data.get("rule", "unknown"))
				.tag("severity", data.get("severity", "info"))
				.field("message", data.get("message", ""))
				.field("src_ip", data.get("src_ip") or "")
				.field("dst_ip", data.get("dst_ip") or "")
				.field("src_port", int(data.get("src_port") or 0))
				.field("dst_port", int(data.get("dst_port") or 0))
			)

			metadata = data.get("metadata") or {}
			for key, value in metadata.items():
				if isinstance(value, (int, float, str)):
					point.field(f"meta_{key}", value)

			timestamp = float(data.get("timestamp", 0))
			if timestamp:
				point.time(self._to_time(timestamp))

			points.append(point)

		if points:
			self.write_api.write(bucket=self.bucket, record=points)

	def write_traffic(self, packets: Iterable[Any]) -> None:
		if not self.enabled or not self.write_traffic_enabled:
			return

		points: list[Point] = []
		for packet in packets:
			data = self._to_dict(packet)
			packet_count = int(data.get("packet_count") or 1)
			payload_bytes = data.get("payload_bytes")
			point = (
				Point("traffic")
				.tag("protocol", data.get("protocol", "UNKNOWN"))
				.tag("src_ip", data.get("src_ip", ""))
				.tag("dst_ip", data.get("dst_ip", ""))
				.field("payload_size", int(data.get("payload_size", 0)))
				.field("packet_count", packet_count)
				.field("src_port", int(data.get("src_port") or 0))
				.field("dst_port", int(data.get("dst_port") or 0))
			)

			if payload_bytes is not None:
				point.field("payload_bytes", int(payload_bytes))

			timestamp = float(data.get("timestamp", 0))
			if timestamp:
				point.time(self._to_time(timestamp))

			points.append(point)

		if points:
			self.write_api.write(bucket=self.bucket, record=points)
