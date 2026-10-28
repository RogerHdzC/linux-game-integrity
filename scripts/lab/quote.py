#!/usr/bin/env python3
"""Lab-only temporary NULL-hierarchy signing key; never a trusted enrollment."""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys


def run(root, tool, *args):
    subprocess.run([tool, '-T', 'device:/dev/tpmrm0', *args], cwd=root,
                   stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                   check=True, timeout=30)


def prepare(root):
    root.mkdir(mode=0o700)  # Refuse to overwrite an existing experiment.
    run(root, 'tpm2_createprimary', '-C', 'n', '-G', 'rsa2048:rsassa-sha256:null', '-g', 'sha256',
        '-a', 'fixedtpm|fixedparent|sensitivedataorigin|userwithauth|restricted|sign', '-c', 'key.ctx')
    run(root, 'tpm2_readpublic', '-c', 'key.ctx', '-f', 'pem', '-o', 'public.pem')


def quote(root, nonce):
    if not re.fullmatch(r'[0-9a-f]{64}', nonce):
        raise ValueError('Expected a 32-byte lowercase hex nonce')
    if (root / 'result.json').exists():
        raise ValueError('This experiment already has a quote')
    run(root, 'tpm2_quote', '-c', 'key.ctx', '-l', 'sha256:0,2,4,7,10', '-q', nonce,
        '-g', 'sha256', '-m', 'quote.bin', '-s', 'signature.bin', '-f', 'tss',
        '-o', 'pcr.bin', '-F', 'values')
    pcrs = (root / 'pcr.bin').read_bytes()
    if len(pcrs) != 160:
        raise ValueError('Unexpected PCR output format')
    result = {'origin': 'live-lab', 'provenance': 'UNPROVEN',
              'publicKey': (root / 'public.pem').read_text(), 'nonce': nonce,
              'quote': {'attest': (root / 'quote.bin').read_bytes().hex(),
                        'signature': (root / 'signature.bin').read_bytes().hex(),
                        'pcrs': [{'index': index, 'digest': pcrs[pos*32:(pos+1)*32].hex()}
                                 for pos, index in enumerate([0, 2, 4, 7, 10])]}}
    with (root / 'result.json').open('x') as stream:
        json.dump(result, stream)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=['prepare', 'quote'])
    parser.add_argument('--directory', type=Path, required=True)
    parser.add_argument('--nonce')
    parser.add_argument('--authorize-temporary-key', action='store_true', required=True)
    args = parser.parse_args()
    os.umask(0o077)
    try:
        if args.operation == 'prepare':
            prepare(args.directory)
        else:
            quote(args.directory, args.nonce or '')
    except subprocess.CalledProcessError as error:
        diagnostic = error.stderr.decode(errors='replace')[:2048]
        if args.directory.is_dir():
            (args.directory / 'failure.txt').write_text(diagnostic)
        print(diagnostic, file=sys.stderr)
        raise SystemExit('TPM tool failed; no trust decision was made.')
    except (OSError, ValueError, subprocess.SubprocessError):
        raise SystemExit('Quote collection failed; no trust decision was made.')
