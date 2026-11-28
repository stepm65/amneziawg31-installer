#!/usr/bin/env python3
"""Print the section of one version from a changelog: `## [0.28.0] — date` up to the next `## [`.
A section may cover a range (`## [0.22.0–0.22.1]`). Prints nothing (exit 1) when there is none.
Usage: changelog-section.py VERSION FILE"""
import re
import sys


def version_key(text):
    return tuple(int(x) for x in text.split('.'))


def section(version, text):
    lines, out, keep = text.splitlines(), [], False
    wanted = version_key(version)
    for line in lines:
        head = re.match(r'^## \[([0-9]+\.[0-9]+\.[0-9]+)(?:[–-]([0-9]+\.[0-9]+\.[0-9]+))?\]', line)
        if head:
            low, high = version_key(head.group(1)), version_key(head.group(2) or head.group(1))
            keep = low <= wanted <= high
            continue
        if keep and (line.startswith('## ') or line.startswith(('Earlier releases', 'Более ранние'))):
            break
        if keep: out.append(line)
    return '\n'.join(out).strip()


if __name__ == '__main__':
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    try:
        body = section(sys.argv[1].lstrip('v'), open(sys.argv[2], encoding='utf-8').read())
    except (OSError, ValueError) as exc:
        sys.exit(f'changelog: {exc}')
    if not body:
        sys.exit(1)
    print(body)
