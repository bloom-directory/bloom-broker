#!/usr/bin/env python3
"""Keep protocol-specific logic out of new Broker source.

Scope: .rs/.js/.html/.css under crates/, excluding tests/, fixtures/, *_tests.rs,
and Rust items explicitly gated by #[cfg(test)]. Catalog JSON is reviewed data,
not executable source. Allowances are exact path/line-text occurrence counts.
"""
import collections
import hashlib
import json
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
BASELINE = ROOT / 'scripts/fixtures/source-guard-master.json'
ALLOWLIST = ROOT / 'scripts/fixtures/source-guard-allowlist.json'
# Frozen from reviewed master history. November merges add only lines present
# verbatim in reviewed_merge_commits; previous_master_commit records the original
# baseline. Changing this is a guard policy change, not an automatic update.
BASELINE_SHA256 = '7083afcf897522448e854636953f7d01f362e1a02ccc29a8d72fd076da53753a'
WORDS = re.compile(r'polymarket|gasless|venice|hyperliquid|near-intents|pendle|privacy-pools|enso|relay|pumpfun', re.I)
LITERALS = re.compile(r'r(#{0,32})".*?"\1|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])\'|//[^\n]*|/\*.*?\*/', re.S)


def source_path(path):
    p = pathlib.PurePosixPath(path)
    return p.parts[0] == 'crates' and p.suffix in {'.rs', '.js', '.html', '.css'} and not {'tests', 'fixtures'} & set(p.parts) and not p.name.endswith('_tests.rs')


def without_rust_tests(source):
    masked = LITERALS.sub(lambda m: ' ' * len(m[0]), source)
    ranges = []
    for match in re.finditer(r'#\s*\[\s*cfg\s*\(\s*test\s*\)\s*\]', masked):
        if any(start <= match.start() < end for start, end in ranges):
            continue
        item = re.search(r'[;{]', masked[match.end():])
        if not item:
            raise ValueError('unterminated test item')
        start = match.end() + item.start()
        end = start + 1
        if masked[start] == '{':
            depth = 1
            while depth and end < len(masked):
                depth += (masked[end] == '{') - (masked[end] == '}')
                end += 1
            if depth:
                raise ValueError('unbalanced test item')
        ranges.append((match.start(), end))
    for start, end in reversed(ranges):
        source = source[:start] + ''.join('\n' if c == '\n' else ' ' for c in source[start:end]) + source[end:]
    return source


def matches(path, source, addresses):
    if path.endswith('.rs'):
        source = without_rust_tests(source)
    return [path + ':' + line.strip() for line in source.splitlines()
            if WORDS.search(line) or any(address in line.lower() for address in addresses)]


def validate_allowlist(baseline, allowlist):
    initial = collections.Counter(baseline['initial_allowlist'])
    master = collections.Counter(baseline['master_matches'])
    allowed = collections.Counter(allowlist)
    if initial - master or allowed - initial:
        raise ValueError('allowlist grew beyond the frozen reviewed baseline; it may only shrink')
    return allowed


def main():
    raw = BASELINE.read_bytes()
    if hashlib.sha256(raw).hexdigest() != BASELINE_SHA256:
        raise ValueError('frozen master baseline changed')
    baseline = json.loads(raw)
    allowed = validate_allowlist(baseline, json.loads(ALLOWLIST.read_text()))
    current = collections.Counter()
    for path in subprocess.check_output(['git', 'ls-files', '--cached', '--others', '--exclude-standard'], cwd=ROOT, text=True).splitlines():
        if source_path(path) and (ROOT / path).is_file():
            current.update(matches(path, (ROOT / path).read_text(), baseline['contract_addresses']))
    added = current - allowed
    if added:
        for line, count in sorted(added.items()):
            print(f'{line} [unallowlisted occurrences: {count}]', file=sys.stderr)
        return 1
    # Exercise the anti-growth rule, including duplicate-occurrence additions.
    try:
        validate_allowlist(baseline, list(allowed.elements()) + ['new.rs:new protocol logic'])
    except ValueError:
        pass
    else:
        raise AssertionError('allowlist growth was accepted')
    print(f'Broker source guard passed: {sum(current.values())} frozen-master occurrences; allowlist may only shrink')
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (ValueError, OSError) as error:
        print(error, file=sys.stderr)
        sys.exit(1)
