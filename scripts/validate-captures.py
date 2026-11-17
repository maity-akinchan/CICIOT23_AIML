#!/usr/bin/env python3
"""Evaluate labeled PCAPs against the deployed model; never used for training.
Manifest JSON: [{"path":"attack.pcap","expected":"DDoS"}]. Token in SENTINEL_OPERATOR_TOKEN.
"""
import argparse,json,os
from pathlib import Path
import requests
p=argparse.ArgumentParser();p.add_argument('manifest',type=Path);p.add_argument('--server',required=True);p.add_argument('--output',type=Path,default=Path('capture-validation.json'));args=p.parse_args()
if not args.server.startswith('https://') and not args.server.startswith(('http://127.0.0.1:','http://localhost:')):p.error('Use HTTPS or localhost')
headers={'Authorization':'Bearer '+os.environ['SENTINEL_OPERATOR_TOKEN']};results=[]
for item in json.loads(args.manifest.read_text()):
    if item['expected'] not in ('Benign','DoS','DDoS'):raise ValueError('Invalid expected class')
    path=args.manifest.parent/item['path']
    with path.open('rb') as f:
        response=requests.post(args.server.rstrip('/')+'/api/v1/pcap/upload',headers=headers,files={'file':(path.name,f)},timeout=180)
    response.raise_for_status();result=response.json();key={'Benign':'benign_count','DoS':'dos_count','DDoS':'ddos_count'}[item['expected']]
    results.append(dict(file=path.name,expected=item['expected'],**result,expected_class_window_fraction=result[key]/result['processed_windows'] if result['processed_windows'] else None))
args.output.write_text(json.dumps({'scope':'Window agreement against file labels; mixed captures require finer ground truth. Approximate measurements; not a training benchmark.','results':results},indent=2))
print(args.output)
