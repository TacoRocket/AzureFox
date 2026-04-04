# AzureFox Wiki

AzureFox is a Python CLI for offensive-focused Azure situational awareness.
This wiki is the operator guide layer: quick starts, walkthroughs, examples, and interpretation
help.

Repo docs remain the source of truth for versioned behavior, output contracts, and roadmap
decisions.

## Start Here

- [Getting Started](Getting-Started)
- [Platform Notes](Platform-Notes)
- [Running Against The Proof Lab](Running-Against-The-Proof-Lab)
- [Understanding Output](Understanding-Output)

## Common First Runs

Install AzureFox:

```bash
pip install azurefox
```

Run a quick identity sanity check:

```bash
azurefox --outdir ./azurefox-demo whoami --output table
```

Run a broader grouped sweep:

```bash
azurefox --outdir ./azurefox-demo all-checks --output table
```

Run one section when you want a narrower grouped pass:

```bash
azurefox --outdir ./azurefox-demo all-checks --section identity --output table
```

The examples use portable relative paths so they read cleanly on macOS, Linux, and Windows.

If you want the short version of platform differences before going deeper, start with
[Platform Notes](Platform-Notes).

## What Lives Where

- Wiki: walkthroughs, operator examples, practical investigation flow
- Repo docs: API mappings, output contracts, release process, roadmap
- CLI help: command-specific usage via `azurefox <command> --help`

## Planned Wiki Areas

- Command Guides
- Common Investigation Paths
- FAQ / Known Limits
