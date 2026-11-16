#!/usr/bin/env python3
# Extracted verbatim from SweepNinja parse_nmap_xmls()
import sys, os, xml.etree.ElementTree as ET, json
xml_dir = sys.argv[1]
results = []
for fname in sorted(os.listdir(xml_dir)):
    if not fname.endswith('.xml'):
        continue
    try:
        tree = ET.parse(os.path.join(xml_dir, fname))
        root = tree.getroot()
    except Exception:
        continue
    for host in root.findall('host'):
        addr_el = host.find("address[@addrtype='ipv4']")
        if addr_el is None:
            continue
        ip = addr_el.get('addr', '')
        ports_el = host.find('ports')
        if ports_el is None:
            continue
        for port_el in ports_el.findall('port'):
            portid   = port_el.get('portid', '')
            protocol = port_el.get('protocol', 'tcp')
            state_el = port_el.find('state')
            if state_el is None or state_el.get('state') != 'open':
                continue
            svc_el = port_el.find('service')
            name=product=version=tunnel=''
            if svc_el is not None:
                name    = svc_el.get('name', '')
                product = svc_el.get('product', '')
                version = svc_el.get('version', '')
                tunnel  = svc_el.get('tunnel', '')
            results.append({'ip':ip,'port':portid,'protocol':protocol,
                            'service':name,'product':product,
                            'version':version,'tunnel':tunnel})
print(json.dumps(results))
