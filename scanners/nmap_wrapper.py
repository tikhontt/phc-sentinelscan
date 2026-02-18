import nmap

def run_nmap_scan(target):
    nm = nmap.PortScanner()
    print(f"[*] (Module) Сканирую {target}...")
    nm.scan(target, arguments='-sV -T4')
    
    hosts_data = []
    for host in nm.all_hosts():
        host_info = {"ip": host, "services": []}
        for proto in nm[host].all_protocols():
            for port in nm[host][proto].keys():
                s_data = nm[host][proto][port]
                host_info["services"].append({
                    "port": port,
                    "name": s_data['name'],
                    "version": f"{s_data.get('product', '')} {s_data.get('version', '')}".strip() or "unknown"
                })
        hosts_data.append(host_info)
    return hosts_data