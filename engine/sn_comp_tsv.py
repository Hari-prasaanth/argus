#!/usr/bin/env python3
# Extracted verbatim from SweepNinja perform_searchsploit()
import json, sys
data = json.load(open(sys.argv[1]))
with open(sys.argv[2], 'w') as f:
    for d in data:
        ips = ', '.join(d['ips'][:5])
        # TSV: product TAB version TAB ips  (tabs safe, newlines delimit entries)
        f.write(f"{d['product']}\t{d['version']}\t{ips}\n")
