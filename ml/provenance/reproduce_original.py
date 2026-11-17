"""Reproduce the pinned supplementary extractor without modifying its formulas."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from urllib.request import urlopen

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('pcap',type=Path);parser.add_argument('output_prefix',type=Path)
    parser.add_argument('--source-dir',type=Path,required=True)
    args=parser.parse_args();args.source_dir.mkdir(parents=True,exist_ok=True)
    manifest=json.loads(Path(__file__).with_name('recovered_sources.json').read_text())
    for name,entry in manifest['files'].items():
        if not name.endswith('.py'):continue
        path=args.source_dir/name
        data=path.read_bytes() if path.exists() else urlopen(entry['url'],timeout=30).read()
        if hashlib.sha256(data).hexdigest()!=entry['sha256']:raise ValueError(f'Checksum mismatch: {name}')
        path.write_bytes(data)
    # Source was reviewed during recovery. Run as its own process with its original imports.
    script='import sys; sys.path.insert(0,sys.argv[1]); from Feature_extraction import Feature_extraction; Feature_extraction().pcap_evaluation(sys.argv[2],sys.argv[3])'
    subprocess.run([sys.executable,'-c',script,str(args.source_dir.resolve()),str(args.pcap.resolve()),str(args.output_prefix.resolve())],check=True)
