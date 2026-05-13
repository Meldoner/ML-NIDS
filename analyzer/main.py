import logging
from typing import Any, Dict, List, Optional

from fastapi import FastAPI
from pydantic import BaseModel, Field

from influx_writer import InfluxDBWriter
from rules import RuleEngine


logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

app = FastAPI(title="NIDS Analyzer")
rule_engine = RuleEngine()
influx_writer = InfluxDBWriter()


class PacketData(BaseModel):
	timestamp: float = Field(..., description="Unix timestamp in seconds")
	src_ip: str
	dst_ip: str
	src_port: Optional[int] = None
	dst_port: Optional[int] = None
	protocol: str
	tcp_flags: Optional[str] = None
	payload_size: int = 0


class PacketBatch(BaseModel):
	packets: List[PacketData]


class Alert(BaseModel):
	timestamp: float
	rule: str
	severity: str
	message: str
	src_ip: Optional[str] = None
	dst_ip: Optional[str] = None
	src_port: Optional[int] = None
	dst_port: Optional[int] = None
	metadata: Dict[str, Any] = Field(default_factory=dict)


@app.post("/api/v1/traffic")
def ingest_traffic(batch: PacketBatch) -> Dict[str, Any]:
	alerts: List[Alert] = []

	for packet in batch.packets:
		for alert_data in rule_engine.process_packet(packet.model_dump()):
			alerts.append(Alert(**alert_data))

	# Future ML integration point: run MLEngine().predict(...) here and merge with rule alerts.

	if alerts:
		influx_writer.write_alerts(alerts)

	influx_writer.write_traffic(batch.packets)

	return {"alert_count": len(alerts), "alerts": alerts}
