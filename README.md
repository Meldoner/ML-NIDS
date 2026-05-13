# ML-NIDS (правил-ориентированный MVP)

Минимальная Network IDS: агент собирает и агрегирует пакеты, анализатор на FastAPI
применяет правила (сигнатуры/пороги) и пишет события в InfluxDB. Архитектура
модульная, чтобы позже добавить ML-детектор.

## Компоненты

- `agent/`: Scapy sniffer, агрегирует пакеты в короткие flow-записи и отправляет батчи.
- `analyzer/`: FastAPI приложение с RuleEngine и записью в InfluxDB.

## Быстрый старт (Docker)

1. Обнови секреты в `docker-compose.yml` (`INFLUXDB_*`, `API_KEY`).
2. Запусти:

```bash
docker compose up --build
```

3. Проверка готовности:

```bash
curl http://localhost:8000/health
```

## Агент (Linux)

Scapy требует права на захват пакетов, поэтому агент запускается под root и
ориентирован на Linux.

Установка зависимостей:

```bash
pip install -r agent/requirements.txt
```

Запуск вручную:

```bash
sudo BACKEND_URL=http://127.0.0.1:8000/api/v1/traffic \
	BACKEND_API_KEY=change_me_api_key \
	python agent/sniffer.py
```

Или установи `agent/ids-agent.service` как systemd-сервис на Debian/Ubuntu.

## API

POST `/api/v1/traffic` принимает батч flow-записей:

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

Если задан `API_KEY` на анализаторе, клиент должен передавать `X-API-Key` с тем же значением.

## Тесты

```bash
pip install -r analyzer/requirements-dev.txt
cd analyzer
pytest
```
