"""Build exactly two allowlisted release files, no workspace or secret packaging."""
import argparse,json
from pathlib import Path
from deploy.protocol import build

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--sha',required=True);parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();manifest,archive=build(args.sha)
    args.output.mkdir(parents=True,exist_ok=True)
    if any(args.output.iterdir()):raise SystemExit('output must be empty')
    (args.output/'site.tar.gz').write_bytes(archive)
    (args.output/'release.json').write_text(json.dumps(manifest,sort_keys=True,separators=(',',':'))+'\n')
    print(manifest['archive_sha256'])
if __name__=='__main__':main()
