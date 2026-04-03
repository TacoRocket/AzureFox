# Getting Started

This page is the fastest path from install to a believable first AzureFox run.

## 1. Install

For most users, the normal install is:

```bash
pip install azurefox
```

If you prefer an isolated environment:

```bash
python -m venv .venv
source .venv/bin/activate
pip install azurefox
```

## 2. Authenticate

AzureFox checks credentials in this order:

1. Azure CLI credential
2. Environment/service principal credential

Browser-based Azure CLI example:

```bash
az login
az account set --subscription <subscription-id>
```

Service principal example:

```bash
export AZURE_TENANT_ID=<tenant-id>
export AZURE_CLIENT_ID=<client-id>
export AZURE_CLIENT_SECRET=<client-secret>
```

## 3. Pick An Output Directory

By default, AzureFox writes artifacts into your current directory.
For ad hoc runs, it is usually cleaner to pass `--outdir` explicitly:

```bash
azurefox --outdir /tmp/azurefox-demo whoami --output table
```

## 4. Run Your First Commands

Check who AzureFox sees you as:

```bash
azurefox --outdir /tmp/azurefox-demo whoami --output table
```

Take a broader inventory pass:

```bash
azurefox --outdir /tmp/azurefox-demo inventory --output table
```

Run a grouped identity sweep:

```bash
azurefox --outdir /tmp/azurefox-demo all-checks --section identity --output table
```

## 5. Ask For Help

AzureFox supports generic and scoped help:

```bash
azurefox help
azurefox help permissions
azurefox whoami --help
```

## Where To Go Next

- Use [Understanding Output](Understanding-Output) to learn where artifacts land and how to read
  them
- Use [Running Against The Proof Lab](Running-Against-The-Proof-Lab) if you want a disposable
  environment for demos and validation
