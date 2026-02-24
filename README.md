# 🛡️ PHC-SentinelScan

**PHC-SentinelScan** — это модульный инструмент для автоматизации сетевой разведки и аудита безопасности веб-заголовков. Проект разработан с учетом принципов DevSecOps: контейнеризация, структурированная отчетность и модульная архитектура.

[![Python](https://img.shields.io/badge/Python-3.10-blue.svg)](https://www.python.org/)
[![Docker](https://img.shields.io/badge/Docker-Enabled-blue.svg)](https://www.docker.com/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

## 🌟 Основные возможности

- **Network Reconnaissance:** Глубокое сканирование портов и определение версий сервисов с помощью Nmap.
- **Web AppSec Audit:** Автоматическая проверка критически важных заголовков безопасности (`CSP`, `HSTS`, `X-Frame-Options`).
- **Modular Design:** Логика сканирования разделена на независимые модули в папке `scanners/`.
- **Automated Reporting:** Генерация технического отчета в `JSON` и наглядной таблицы в `Markdown`.

## 🛠 Архитектура проекта

Проект организован по модульному принципу:
- `main.py`: Управляющий скрипт (оркестратор).
- `scanners/`: Пакет с модулями сканирования (Nmap, Web-checker).
- `reports/`: Директория для результатов (автоматически монтируется через Docker Volume).

## 🚀 Быстрый старт

### Требования
- Установленный [Docker](https://docs.docker.com/get-docker/)

### Сборка и запуск
1. Склонируйте репозиторий:
   ```bash
   git clone [https://github.com/tikhontt/phc-sentinelscan.git](https://github.com/tikhontt/phc-sentinelscan.git)
   cd phc-sentinelscan

2. Соберите Docker-образ:
  ```bash
  sudo docker build -t sentinel-scan .
  ```
3. Запустите сканирование:
   ```bash
   sudo docker run --rm -it -v "$(pwd)/reports:/app/reports" sentinel-scan scanme.nmap.org
   ```

**Примечание:** Результаты (JSON и подробная таблица) автоматически появятся в папке reports/ в корне вашего проекта.

## 📊 Пример отчета (REPORT.md)

| Порт | Сервис | Версия | Безопасность (Заголовки) |
|:---|:---|:---|:---|
| **22** | ssh | OpenSSH 8.2p1 | 🔍 Service Detected |
| **80** | http | Apache 2.4.41 | ✅ CSP<br>❌ HSTS<br>✅ X-Frame-Options |
| **443** | https | nginx 1.18.0 | ✅ CSP<br>✅ HSTS<br>✅ X-Frame-Options |

## 🗺️ Roadmap развития
- [ ] **Vulnerability Lookup:** Интеграция с API (CVE Search) для поиска уязвимостей по версиям ПО.
- [ ] **Telegram Bot:** Отправка уведомлений о завершении сканирования.
- [ ] **Multi-target:** Поддержка сканирования списка IP-адресов из файла.
