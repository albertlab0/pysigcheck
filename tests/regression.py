#!/usr/bin/env python3
"""Regression harness for pysigcheck.

The sample collection lives in ``tests/samples/`` and is never committed - it
holds live malware. Samples are stored with a ``.sample`` suffix so they cannot
be launched by a double-click; pysigcheck does not care about the extension.

Usage::

    # Add a sample, snapshotting today's output as the expectation
    python tests/regression.py add C:\\virus\\...\\thing.exe --name certum-cross-sign

    # Add a sample but assert a verdict you established independently
    python tests/regression.py add ... --verified Signed --note "sigcheck says signed"

    # Reference a file in place instead of copying it (system binaries)
    python tests/regression.py add C:\\Windows\\System32\\notepad.exe --live

    # Run the suite
    python tests/regression.py run
    python tests/regression.py run --verbose
"""

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SAMPLE_DIR = os.path.join(HERE, "samples")
MANIFEST = os.path.join(SAMPLE_DIR, "manifest.json")
PYSIGCHECK = os.path.join(os.path.dirname(HERE), "pysigcheck.py")

# Fields recorded as expectations when none are given explicitly. Deliberately
# excludes anything environment-dependent (Link date is derived from the PE, so
# it is stable, but catalog signing dates move when the OS is patched).
SNAPSHOT_FIELDS = [
    "Verified",
    "Publisher",
    "Company",
    "Description",
    "Product",
    "Prod version",
    "File version",
    "MachineType",
    "MD5",
    "SHA1",
    "PESHA1",
    "PE256",
    "SHA256",
    "IMP",
    "Link date",
]


def load_manifest():
    if not os.path.isfile(MANIFEST):
        return {"samples": []}
    with open(MANIFEST, encoding="utf-8") as f:
        return json.load(f)


def save_manifest(manifest):
    os.makedirs(SAMPLE_DIR, exist_ok=True)
    with open(MANIFEST, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2, ensure_ascii=False)
        f.write("\n")


def sha256_of(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest().upper()


def run_pysigcheck(path):
    """Run pysigcheck on a path and return (parsed_fields, raw_stdout)."""
    env = dict(os.environ, PYTHONIOENCODING="utf-8")
    proc = subprocess.run(
        [sys.executable, PYSIGCHECK, path],
        capture_output=True,
        env=env,
    )
    out = proc.stdout.decode("utf-8", errors="replace")
    if proc.returncode != 0:
        err = proc.stderr.decode("utf-8", errors="replace")
        raise RuntimeError(f"pysigcheck exited {proc.returncode}:\n{err}")

    fields = {}
    for line in out.splitlines():
        m = re.match(r"^\t([^:]+):\t(.*)$", line)
        if m:
            fields[m.group(1)] = m.group(2)
    return fields, out


def resolve(entry):
    """Return the on-disk path for a manifest entry."""
    if entry.get("live"):
        return entry["origin"]
    return os.path.join(SAMPLE_DIR, entry["file"])


def cmd_add(args):
    src = os.path.abspath(args.path)
    if not os.path.isfile(src):
        sys.exit(f"error: not a file: {src}")

    manifest = load_manifest()
    name = args.name or os.path.basename(src)
    if any(e["name"] == name for e in manifest["samples"]):
        sys.exit(f"error: sample {name!r} already exists (use a different --name)")

    entry = {
        "name": name,
        "origin": src,
        "sha256": sha256_of(src),
        "live": bool(args.live),
    }
    if args.note:
        entry["note"] = args.note

    if args.live:
        target = src
    else:
        os.makedirs(SAMPLE_DIR, exist_ok=True)
        entry["file"] = os.path.basename(src) + ".sample"
        target = os.path.join(SAMPLE_DIR, entry["file"])
        shutil.copy2(src, target)

    fields, _ = run_pysigcheck(target)
    if args.expect:
        expect = {}
        for item in args.expect:
            key, _, value = item.partition("=")
            expect[key.strip()] = value
    else:
        expect = {k: fields[k] for k in SNAPSHOT_FIELDS if k in fields}

    if args.verified:
        if fields.get("Verified") != args.verified:
            print(
                f"warning: pysigcheck currently reports"
                f" Verified={fields.get('Verified')!r}, recording the asserted"
                f" {args.verified!r} - this sample will FAIL until that is fixed"
            )
        expect["Verified"] = args.verified

    entry["expect"] = expect
    manifest["samples"].append(entry)
    save_manifest(manifest)

    print(f"added {name!r} ({'in place' if args.live else entry['file']})")
    for key, value in expect.items():
        print(f"  {key}: {value}")


def cmd_run(args):
    manifest = load_manifest()
    samples = manifest["samples"]
    if not samples:
        print(f"no samples in {SAMPLE_DIR} - add some with 'regression.py add'")
        return 0

    failures = 0
    skipped = 0
    for entry in samples:
        name = entry["name"]
        path = resolve(entry)

        if not os.path.isfile(path):
            print(f"SKIP {name}: missing {path}")
            skipped += 1
            continue

        try:
            fields, raw = run_pysigcheck(path)
        except RuntimeError as exc:
            print(f"FAIL {name}: {exc}")
            failures += 1
            continue

        diffs = [
            (key, want, fields.get(key, "<missing>"))
            for key, want in entry["expect"].items()
            if fields.get(key, "<missing>") != want
        ]

        if diffs:
            failures += 1
            print(f"FAIL {name}")
            if entry.get("note"):
                print(f"     note: {entry['note']}")
            for key, want, got in diffs:
                print(f"     {key}: expected {want!r}, got {got!r}")
            if args.verbose:
                print("     --- actual output ---")
                for line in raw.splitlines():
                    print(f"     {line}")
        else:
            print(f"PASS {name}")
            if args.verbose:
                for line in raw.splitlines():
                    print(f"     {line}")

    total = len(samples)
    print(
        f"\n{total - failures - skipped} passed, {failures} failed,"
        f" {skipped} skipped (of {total})"
    )
    return 1 if failures else 0


def cmd_list(args):
    manifest = load_manifest()
    if not manifest["samples"]:
        print("no samples")
        return 0
    for entry in manifest["samples"]:
        where = "in place" if entry.get("live") else entry.get("file")
        print(f"{entry['name']}  [{where}]")
        if entry.get("note"):
            print(f"  {entry['note']}")
        print(f"  Verified: {entry['expect'].get('Verified', '?')}")
    return 0


def cmd_rerecord(args):
    """Refresh the recorded expectations from the current pysigcheck output."""
    manifest = load_manifest()
    changed = 0
    for entry in manifest["samples"]:
        if args.name and entry["name"] != args.name:
            continue
        path = resolve(entry)
        if not os.path.isfile(path):
            print(f"SKIP {entry['name']}: missing {path}")
            continue
        fields, _ = run_pysigcheck(path)
        new = {k: fields[k] for k in entry["expect"] if k in fields}
        if new != entry["expect"]:
            print(f"updated {entry['name']}")
            for key, value in new.items():
                if entry["expect"].get(key) != value:
                    print(f"  {key}: {entry['expect'].get(key)!r} -> {value!r}")
            entry["expect"] = new
            changed += 1
    if changed:
        save_manifest(manifest)
    print(f"{changed} sample(s) updated")
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)

    p_add = sub.add_parser("add", help="add a file to the sample collection")
    p_add.add_argument("path", help="file to add")
    p_add.add_argument("--name", help="short identifier (default: file name)")
    p_add.add_argument(
        "--live",
        action="store_true",
        help="reference the file where it is instead of copying it in",
    )
    p_add.add_argument(
        "--verified",
        choices=["Signed", "Unsigned"],
        help="assert this verdict rather than snapshotting the current one",
    )
    p_add.add_argument(
        "--expect",
        action="append",
        metavar="KEY=VALUE",
        help="record only these fields (repeatable)",
    )
    p_add.add_argument("--note", help="why this sample is interesting")
    p_add.set_defaults(func=cmd_add)

    p_run = sub.add_parser("run", help="run the suite")
    p_run.add_argument("-v", "--verbose", action="store_true")
    p_run.set_defaults(func=cmd_run)

    p_list = sub.add_parser("list", help="list samples")
    p_list.set_defaults(func=cmd_list)

    p_rr = sub.add_parser("rerecord", help="refresh expectations from current output")
    p_rr.add_argument("--name", help="only this sample")
    p_rr.set_defaults(func=cmd_rerecord)

    args = parser.parse_args()
    sys.exit(args.func(args) or 0)


if __name__ == "__main__":
    main()
