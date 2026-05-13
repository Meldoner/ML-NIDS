# ML-NIDS (Rule-Based MVP)

This project is a minimal Network IDS that collects packets on the agent side and
analyzes them in a FastAPI backend using signature/threshold rules. The design is
modular so an ML detector can be added later.

## Components

- `agent/`: Scapy sniffer that aggregates packets into short flows and sends batches.
- `analyzer/`: FastAPI app with RuleEngine and InfluxDB writer.

## Quickstart (Docker)

1. Update secrets in `docker-compose.yml` (`INFLUXDB_*`, `API_KEY`).
2. Run:

```bash
docker compose up --build
```

3. Check health:

```bash
curl http://localhost:8000/health
```

## Agent (Linux)

Install dependencies:

```bash
pip install -r agent/requirements.txt
```

Run directly:

```bash
sudo BACKEND_URL=http://127.0.0.1:8000/api/v1/traffic \
	BACKEND_API_KEY=change_me_api_key \
	python agent/sniffer.py
```

Or install `agent/ids-agent.service` as a systemd service on Debian/Ubuntu.

## API

POST `/api/v1/traffic` accepts a batch of flow records:

```json
{
	"packets": [
		{
			"timestamp": 1710000000.123,
			"first_seen": 1710000000.001,
			"last_seen": 1710000000.123,
			"src_ip": "10.0.0.10",
			"dst_ip": "10.0.0.20",
			"src_port": 44444,
			"dst_port": 80,
			"protocol": "TCP",
			"tcp_flags": "S",
			"payload_size": 0,
			"packet_count": 12,
			"payload_bytes": 0,
			"syn_count": 12,
			"ack_count": 0
		}
	]
}
```

If `API_KEY` is set on the analyzer, clients must send `X-API-Key` with the same value.

## Tests

```bash
pip install -r analyzer/requirements-dev.txt
cd analyzer
pytest
```
