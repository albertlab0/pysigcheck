# pysigcheck regression samples

`regression.py` is a snapshot-test harness. The sample collection it drives lives
in `tests/samples/` and is **gitignored** — it holds live malware, so it must
never be committed. `manifest.json` (the recorded expectations) lives inside that
folder too, since it is meaningless without the binaries it describes.

Copied samples are stored with a `.sample` suffix appended so they can't be
launched by a double-click. pysigcheck identifies PEs by the `MZ` header, not the
extension, so this doesn't change what's tested.

## Commands

```bash
python tests/regression.py run              # run the suite
python tests/regression.py run --verbose    # also print each sample's full output
python tests/regression.py list
python tests/regression.py rerecord         # accept current output as expected
```

## Adding a sample

```bash
# Copy it in and snapshot the current output as the expectation
python tests/regression.py add C:\virus\...\thing.exe --name short-id --note "why"

# Assert a verdict you established independently (e.g. from real sigcheck).
# Warns if pysigcheck currently disagrees, so you can add a failing sample first.
python tests/regression.py add ... --verified Signed

# Record only specific fields (repeatable) instead of the full snapshot
python tests/regression.py add ... --expect "Verified=Signed" --expect "Publisher=Microsoft Windows"

# Reference the file in place rather than copying it — for system binaries
python tests/regression.py add C:\Windows\System32\notepad.exe --live
```

`--live` entries are skipped (not failed) when the path is missing, so the suite
still runs on a machine without them.

## Choosing expectations

The default snapshot records every stable field — hashes, version resources,
`MachineType`, `Link date`. For samples whose result depends on the machine, pin
only what's actually invariant:

- **Catalog-signed system files** resolve through the local `CatRoot`, and their
  signing date moves with OS patch level. Assert `Verified` and `Publisher` only.
- **Hashes and version resources** are properties of the file, so they're safe to
  snapshot for anything copied into `samples/`.

## Current samples

| Name | What it covers |
| --- | --- |
| `certum-cross-signed-timestamp` | Timestamp chain that only validates via a cross-signed root; signify alone reports `COUNTERSIGNER_ERROR`. Also carries a CJK publisher name, which used to crash output on a cp1252 console. |
| `catalog-signed-notepad` | Catalog signature with no embedded signature — needs the `CryptCATAdmin*` lookup. |
| `embedded-signed-kernel32` | Ordinary embedded Microsoft signature. |
| `unsigned-pe-with-version-info` | Unsigned PE that still carries vendor version resources, so version info alone can't imply "Signed". |
| `non-pe-hosts-file` | Non-PE input: hashes only, no `Verified` line. |
