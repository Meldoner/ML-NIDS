# USAGE

Документ описывает порядок запуска и тестирования ML-NIDS (MVP) на Linux.

## 1. Предварительные требования

- Linux-хост для агента (нужны root или NET_RAW/NET_ADMIN).
- Docker и Docker Compose для анализатора, InfluxDB и Grafana.
- Python 3.10+ для агента.
- libpcap инструменты (рекомендуется): `tcpdump`.

## 2. Конфигурация стека (Docker)

В [docker-compose.yml](docker-compose.yml) требуется задать:

- `INFLUXDB_TOKEN`
- `INFLUXDB_ORG`
- `INFLUXDB_BUCKET`
- `API_KEY` (опционально, но рекомендуется)

Запуск инфраструктуры:

```bash
docker compose up --build
```

Проверка доступности API:

```bash
curl http://localhost:8000/health
```

## 3. Запуск агента на Linux

Установка зависимостей:

```bash
pip install -r agent/requirements.txt
```

Выбор интерфейса:

```bash
ip link show
```

Пример запуска агента:

```bash
export BACKEND_URL=http://127.0.0.1:8000/api/v1/traffic
export BACKEND_API_KEY=change_me_api_key
export SNIFF_INTERFACE=eth0
export BPF_FILTER=ip
sudo -E python agent/sniffer.py
```

Примечания:
- `BPF_FILTER=ip` означает захват всего IP-трафика на интерфейсе.
- Для более узкого захвата можно использовать фильтр вида `tcp and port 80`.

## 4. Запуск как systemd-сервис (Linux)

1. Копирование и установка файла сервиса:

```bash
sudo mkdir -p /opt/ids-agent
sudo cp agent/sniffer.py /opt/ids-agent/
sudo cp agent/ids-agent.service /etc/systemd/system/ids-agent.service
sudo systemctl daemon-reload
```

2. В `/etc/systemd/system/ids-agent.service` указываются:

- `WorkingDirectory`
- `ExecStart`
- `Environment=BACKEND_URL=...`
- `Environment=BACKEND_API_KEY=...`
- `Environment=SNIFF_INTERFACE=...`

3. Запуск сервиса:

```bash
sudo systemctl enable ids-agent
sudo systemctl start ids-agent
sudo systemctl status ids-agent
```

## 5. Ручная отправка тестового батча

Для проверки без реального sniff можно отправить синтетический батч,
который должен вызвать SYN flood alert.

```bash
curl -X POST http://localhost:8000/api/v1/traffic \
  -H "Content-Type: application/json" \
  -H "X-API-Key: change_me_api_key" \
  -d '{"packets":[{"timestamp":'"$(date +%s)"',"src_ip":"10.0.0.1","dst_ip":"10.0.0.2","src_port":1234,"dst_port":80,"protocol":"TCP","tcp_flags":"S","payload_size":0,"syn_count":60}]}'
```

Если `API_KEY` не задан, заголовок `X-API-Key` не используется.

## 6. Тестирование реальным трафиком (только лаборатория)

Тестирование допускается только в собственной лаборатории или с явного разрешения.

Port scan:

```bash
nmap -p 1-50 <TARGET_IP>
```

Large ICMP:

```bash
ping -s 1200 -c 3 <TARGET_IP>
```

SYN flood (безопасный тест):

```bash
sudo hping3 -S -p 80 -c 60 -i u10000 <TARGET_IP>
```

## 7. Дашборд Grafana

1. Открыть Grafana: `http://localhost:3000` (логин/пароль `admin/admin`).
2. Добавить data source: InfluxDB 2.x.
3. URL внутри Docker Compose: `http://influxdb:8086`.
4. Указать Org, Bucket, Token в соответствии с [docker-compose.yml](docker-compose.yml).

Пример Flux-запроса для алертов:

```flux
from(bucket: "change_me_bucket")
  |> range(start: -1h)
  |> filter(fn: (r) => r._measurement == "alerts")
  |> pivot(rowKey: ["_time"], columnKey: ["_field"], valueColumn: "_value")
```

## 8. Troubleshooting

- Нет алертов в Grafana: проверить диапазон времени и корректность timestamp.
- Несовпадение API ключа: анализатор возвращает 401 и не пишет данные.
- Токены InfluxDB изменены после первого запуска: требуется обновить переменные окружения или пересоздать volume.
- Вкладка "Alerts" в InfluxDB не содержит IDS алерты, используются Data Explorer и измерение `alerts`.
