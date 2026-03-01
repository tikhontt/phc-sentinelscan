import sys
import json
import os
from scanners.nmap_wrapper import run_nmap_scan
from scanners.web_wrapper import check_headers
from scanners.ssl_checker import check_ssl

def save_markdown_report(data, folder):
    """Генерирует наглядный отчет в формате Markdown"""
    report_path = os.path.join(folder, "REPORT.md")
    print(f"[*] Генерирую итоговый Markdown: {report_path}")
    
    try:
        with open(report_path, "w", encoding="utf-8") as f:
            f.write("# 🛡️ SentinelScan Security Report\n\n")
            
            if not data:
                f.write("## ⚠️ Данные не найдены. Проверьте доступность цели.\n")
                return

            f.write(f"> **Цель сканирования:** `{data[0].get('ip', 'Unknown')}`  \n")
            f.write(f"> **Статус:** Завершено успешно ✅  \n\n")
            
            for host in data:
                f.write(f"### 🌐 Хост: {host['ip']}\n")
                f.write("| Порт | Сервис | Версия | Безопасность (Аудит) |\n")
                f.write("|:---|:---|:---|:---|\n")
                
                for s in host.get('services', []):
                    status_parts = []

                    headers = s.get('security_headers', {})
                    if isinstance(headers, dict) and "error" not in headers:
                        for k, v in headers.items():
                            icon = "✅" if v != "MISSING" else "❌"
                            status_parts.append(f"{icon} {k}")
                    elif isinstance(headers, dict) and "error" in headers:
                        status_parts.append(f"⚠️ {headers['error']}")

                    ssl = s.get('ssl_info')
                    if ssl and isinstance(ssl, dict) and "error" not in ssl:
                        days = ssl.get('days_left', '?')
                        status_parts.append(f"🔒 SSL: {days} дн.")
                    elif ssl and isinstance(ssl, dict) and "error" in ssl:
                        status_parts.append(f"❌ SSL: {ssl['error']}")

                    if not status_parts:
                        status_parts.append("🔍 Service Active")

                    status_str = "<br>".join(status_parts)
                    f.write(f"| **{s['port']}** | {s['name']} | {s['version']} | {status_str} |\n")
                
                f.write("\n---\n")
        
        print(f"[+ SUCCESS] REPORT.md успешно создан в папке '{folder}'")

    except IOError as e:
        print(f"[! ERROR] Ошибка записи файла (права доступа?): {e}")
    except Exception as e:
        print(f"[! ERROR] Что-то пошло совсем не так при генерации MD: {e}")



if __name__ == "__main__":
    target_ip = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    output_dir = "reports"
    
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    print(f"--- SentinelScan запущен для цели: {target_ip} ---")

    results = run_nmap_scan(target_ip)
    
    if not results:
        print("[!] Сканирование не дало результатов. Выход.")
        sys.exit(1)

    for host in results:
        for service in host['services']:
            if service['port'] in [80, 443]:
                print(f"[*] Проверка HTTP-заголовков для {host['ip']}:{service['port']}...")
                service['security_headers'] = check_headers(host['ip'], service['port'])
            
            if service['port'] == 443:
                print(f"[*] Запуск SSL/TLS аудита для {host['ip']}:443...")
                service['ssl_info'] = check_ssl(host['ip'], service['port'])

    json_path = os.path.join(output_dir, "last_scan.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=4, ensure_ascii=False)
    print(f"[+] JSON отчет сохранен: {json_path}")

    save_markdown_report(results, output_dir)
    
    print("--- Работа завершена ---")
