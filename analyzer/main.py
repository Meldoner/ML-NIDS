import logging
import os
from typing import Any, Dict, List, Optional

from fastapi import Depends, FastAPI, Header, HTTPException, status
from pydantic import BaseModel, Field

from influx_writer import InfluxDBWriter
from rules import RuleEngine


logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

app = FastAPI(title="NIDS Analyzer")
rule_engine = RuleEngine()
influx_writer = InfluxDBWriter()
API_KEY = os.getenv("API_KEY")


class PacketData(BaseModel):
	timestamp: float = Field(..., description="Unix timestamp in seconds")
	first_seen: Optional[float] = None
	last_seen: Optional[float] = None
	src_ip: str
	dst_ip: str
	src_port: Optional[int] = None
	dst_port: Optional[int] = None
	protocol: str
	tcp_flags: Optional[str] = None
	payload_size: int = 0
	packet_count: Optional[int] = None
	payload_bytes: Optional[int] = None
	syn_count: Optional[int] = None
	ack_count: Optional[int] = None


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


def verify_api_key(x_api_key: Optional[str] = Header(default=None)) -> None:
	if API_KEY and x_api_key != API_KEY:
		raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid API key")


@app.post("/api/v1/traffic")
def ingest_traffic(batch: PacketBatch, _: None = Depends(verify_api_key)) -> Dict[str, Any]:
	alerts: List[Alert] = []

	for packet in batch.packets:
		for alert_data in rule_engine.process_packet(packet.model_dump()):
			alerts.append(Alert(**alert_data))

	# Future ML integration point: run MLEngine().predict(...) here and merge with rule alerts.

	if alerts:
		influx_writer.write_alerts(alerts)

	influx_writer.write_traffic(batch.packets)

	return {"alert_count": len(alerts), "alerts": alerts}
