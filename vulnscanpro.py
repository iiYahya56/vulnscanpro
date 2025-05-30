import subprocess
import xml.etree.ElementTree as ET
import requests
import argparse
from jinja2 import Environment, FileSystemLoader
import os

# ============ CVE Lookup ============
def search_vulners(service_name, version):
    query = f"{service_name} {version}"
    url = "https://vulners.com/api/v3/search/lucene/"
    params = {
        "query": query,
        "apiKey": "YOUR_VULNERS_API_KEY"  # <-- replace this
    }
    try:
        res = requests.get(url, params=params)
        res.raise_for_status()
        data = res.json()
        cve_list = []
        for item in data['data']['search']:
            if item['type'] == 'cve':
                cve_list.append({
                    'id': item.get('id'),
                    'cvss': item.get('cvss', 0),
                    'description': item.get('description', 'No description.'),
                    'published': item.get('published'),
                    'href': item.get('href'),
                })
        return cve_list
    except Exception as e:
        print(f"[!] Error querying Vulners: {e}")
        return []

# ============ Nmap Parser ============
def parse_nmap_output(xml_file):
    tree = ET.parse(xml_file)
    root = tree.getroot()
    host = root.find("host/address").attrib.get("addr")
    services = []

    for port in root.findall(".//port"):
        port_id = port.attrib['portid']
        protocol = port.attrib['protocol']
        state = port.find("state").attrib['state']
        service_el = port.find("service")

        if service_el is not None and state == "open":
            name = service_el.attrib.get("name", "")
            version = service_el.attrib.get("version", "")
            product = service_el.attrib.get("product", "")
            services.append({
                'port': port_id,
                'protocol': protocol,
                'product': product,
                'version': version,
                'name': name
            })
    return host, services

# ============ HTML Report =============
def generate_report(host, results, output_path):
    env = Environment(loader=FileSystemLoader("templates"))
    template = env.get_template("report_template.html")
    html_content = template.render(host=host, results=results)

    with open(output_path, "w") as f:
        f.write(html_content)
    print(f"[+] Report generated at {output_path}")

# ============ Main Entry =============
def run_nmap(target):
    xml_output = "scan_result.xml"
    cmd = ["nmap", "-sV", "-oX", xml_output, target]
    print(f"[+] Running Nmap on {target}...")
    subprocess.run(cmd, check=True)
    return xml_output

def main():
    parser = argparse.ArgumentParser(description="Vulnerability Scanner + CVE Lookup + HTML Report")
    parser.add_argument("target", help="Target IP or domain")
    parser.add_argument("--report", default="vulnscan_report.html", help="Output report file")
    args = parser.parse_args()

    xml_path = run_nmap(args.target)
    host, services = parse_nmap_output(xml_path)

    results = []
    for svc in services:
        print(f"[*] Searching CVEs for {svc['product']} {svc['version']}...")
        vulns = search_vulners(svc['product'], svc['version'])
        svc['vulnerabilities'] = vulns
        results.append(svc)

    generate_report(host, results, args.report)

if __name__ == "__main__":
    main()
