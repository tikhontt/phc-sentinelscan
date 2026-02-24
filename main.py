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

            f.write(f"> **Цель сканирования:** `{data[0]['ip']}`  \n")
            f.write(f"> **Статус:** Завершено успешно ✅  \n\n")
            
            for host in data:
                f.write(f"### 🌐 Хост: {host['ip']}\n")
                f.write("| Порт | Сервис | Версия | Безопасность (Заголовки) |\n")
                f.write("|:---|:---|:---|:---|\n")
                
                for s in host['services']:
                    headers = s.get('security_headers', {})
                    if 'ssl_info' in s and "error" not in s['ssl_info']:
                        ssl = s['ssl_info']
                        ssl_str = f"📅 Срок: {ssl['days_left']} дн."
                        status_str += f"<br>🔒 {ssl_str}"
                    if isinstance(headers, dict) and "error" not in headers:
                        h_list = []
                        for k, v in headers.items():
                            icon = "✅" if v != "MISSING" else "❌"
                            h_list.append(f"{icon} {k}")
                        status_str = "<br>".join(h_list)
                    elif s['port'] in [80, 443]:
                        status_str = "⚠️ Ошибка проверки (Timeout/Refused)"
                    else:
                        status_str = "🔍 Сервис активен"
                    
                    f.write(f"| **{s['port']}** | {s['name']} | {s['version']} | {status_str} |\n")
                f.write("\n---\n")
        print("[+ SUCCESS] REPORT.md успешно создан!")
    except Exception as e:
        print(f"[! ERROR] Ошибка записи MD: {e}")

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
            # Проверяем заголовки (HTTP)
            if service['port'] in [80, 443]:
                print(f"[*] Проверка HTTP-заголовков для {host['ip']}:{service['port']}...")
                service['security_headers'] = check_headers(host['ip'], service['port'])
            
            # Проверяем SSL (HTTPS)
            if service['port'] == 443:
                print(f"[*] Запуск SSL/TLS аудита для {host['ip']}:443...")
                service['ssl_info'] = check_ssl(host['ip'], service['port'])

    json_path = os.path.join(output_dir, "last_scan.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=4, ensure_ascii=False)
    print(f"[+] JSON отчет сохранен: {json_path}")

    save_markdown_report(results, output_dir)
    
    print("--- Работа завершена ---")
