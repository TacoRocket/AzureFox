# Platform Notes

AzureFox is intended to be operator-usable on macOS, Linux, and Windows.

The CLI itself is mostly platform-neutral. The differences you are most likely to notice are shell
syntax and path style, not AzureFox command behavior.

## What Should Feel The Same

- `pip install azurefox`
- `azurefox <command>`
- `--tenant`, `--subscription`, `--output`, `--outdir`, and `--debug`
- JSON, table, CSV, and loot artifact layout under the chosen output directory

## What Usually Differs By Platform

### Virtual Environment Activation

```bash
# macOS/Linux
python -m venv .venv
source .venv/bin/activate
```

```powershell
# Windows PowerShell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

### Service Principal Environment Variables

```bash
# macOS/Linux
export AZURE_TENANT_ID=<tenant-id>
export AZURE_CLIENT_ID=<client-id>
export AZURE_CLIENT_SECRET=<client-secret>
```

```powershell
# Windows PowerShell
$env:AZURE_TENANT_ID="<tenant-id>"
$env:AZURE_CLIENT_ID="<client-id>"
$env:AZURE_CLIENT_SECRET="<client-secret>"
```

### Output Directory Examples

Wiki and README examples prefer relative paths such as `./azurefox-demo`.

That is intentional:

- it avoids over-biasing toward `/tmp/...`
- it reads cleanly on macOS, Linux, and Windows
- it makes it obvious that artifacts go wherever you point `--outdir`

If you already have a preferred scratch directory, use that instead.

## What Is More Maintainer-Oriented

Some repo docs still show Unix-style shell examples for release or packaging work.
That does not mean AzureFox is meant to be Unix-only. It only means the maintainer workflow docs
currently reflect the environment they were authored in.

## Practical Recommendation

For first runs on any platform:

```bash
pip install azurefox
azurefox --outdir ./azurefox-demo whoami --output table
```

If that works, the rest of the command surface should feel familiar.
