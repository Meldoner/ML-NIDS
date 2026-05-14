# ML-NIDS (rule-based MVP)

Network IDS уровня MVP: агент собирает и агрегирует пакеты, анализатор на FastAPI
применяет rule-based правила и записывает события в InfluxDB. Архитектура
модульная и предусматривает расширение до ML-детектора.

## Возможности

- Захват трафика и flow-агрегация на агенте.
- RuleEngine с набором правил: SynFlood, SynAckImbalance, PortScan,
	HorizontalScan, MultiTargetScan, UdpFlood, IcmpFlood, LargeIcmp, TcpFlagAnomaly.
- Наблюдаемость: InfluxDB + Grafana.
- Опциональная аутентификация по API ключу.

## Документация

- Подробная инструкция запуска и тестирования: [USAGE.md](USAGE.md)
- Архитектура по arc42: [docs/architecture-arc42.md](docs/architecture-arc42.md)
- Диаграмма: [docs/diagram.puml](docs/diagram.puml)

## Компоненты

- `agent/`: Scapy sniffer, агрегирует пакеты в короткие flow-записи и отправляет батчи.
- `analyzer/`: FastAPI приложение с RuleEngine и записью в InfluxDB.
- `docker-compose.yml`: InfluxDB и Grafana для хранения и визуализации.

## Требования

- Linux для агента (нужны права на захват пакетов).
- Docker и Docker Compose для анализатора, InfluxDB и Grafana.
- Python 3.10+ для агента.

## Запуск (кратко)

Конфигурация задается в [docker-compose.yml](docker-compose.yml) через `INFLUXDB_*` и `API_KEY`.
Запуск инфраструктуры выполняется командой:

```bash
docker compose up --build
```

Проверка доступности API:

```bash
curl http://localhost:8000/health
```

## Переменные окружения

Analyzer (обычно задаются в [docker-compose.yml](docker-compose.yml)):

| Переменная | Значение по умолчанию | Назначение | Обязательная |
| --- | --- | --- | --- |
| `INFLUXDB_URL` | `http://localhost:8086` | URL InfluxDB | Да |
| `INFLUXDB_TOKEN` | — | Токен доступа InfluxDB | Да |
| `INFLUXDB_ORG` | — | Организация InfluxDB | Да |
| `INFLUXDB_BUCKET` | — | Bucket для записи | Да |
| `INFLUX_WRITE_TRAFFIC` | `1` | Запись метрик трафика (`1`/`0`) | Нет |
| `API_KEY` | — | API ключ для входящих запросов | Нет |

Agent (задаются при запуске или в systemd):

| Переменная | Значение по умолчанию | Назначение | Обязательная |
| --- | --- | --- | --- |
| `BACKEND_URL` | `http://127.0.0.1:8000/api/v1/traffic` | URL анализатора | Да |
| `BACKEND_API_KEY` | — | API ключ для запросов к анализатору | Нет |
| `API_KEY_HEADER` | `X-API-Key` | Заголовок API ключа | Нет |
| `SNIFF_INTERFACE` | — | Интерфейс захвата (например, `eth0`) | Да |
| `BPF_FILTER` | `ip` | BPF фильтр трафика | Нет |
| `BATCH_INTERVAL` | `1.5` | Интервал отправки батча (сек) | Нет |
| `BATCH_MAX_SIZE` | `500` | Максимальный размер батча | Нет |
| `MAX_BUFFER_SIZE` | `5000` | Максимальный размер буфера | Нет |
| `CONNECT_TIMEOUT` | `3` | Таймаут подключения (сек) | Нет |
| `READ_TIMEOUT` | `5` | Таймаут чтения (сек) | Нет |

## Агент (Linux)

Агент запускается от root из-за требований Scapy к захвату пакетов. Пример запуска:

```bash
sudo BACKEND_URL=http://127.0.0.1:8000/api/v1/traffic \
	BACKEND_API_KEY=change_me_api_key \
	python agent/sniffer.py
```

Альтернативно используется systemd-шаблон: [agent/ids-agent.service](agent/ids-agent.service).

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

Если задан `API_KEY` на анализаторе, клиент передает `X-API-Key` с тем же значением.

## Тесты

Unit-тесты правил выполняются из каталога анализатора:

```bash
pip install -r analyzer/requirements-dev.txt
cd analyzer
pytest
```

## Лицензия

Проект распространяется на условиях MIT: [LICENSE](LICENSE)
