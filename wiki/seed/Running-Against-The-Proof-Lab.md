# Running Against The Proof Lab

If you do not already have a safe Azure environment for demos or testing, use the companion proof
lab:

- [AzureFox OpenTofu Proof Lab](https://github.com/TacoRocket/terraform-labs-for-azurefox)

Use a disposable subscription you control.
The lab is intentionally insecure and is meant for practice, validation, and walkthroughs.

## Suggested Operator Flow

1. Build the lab by following the proof-lab repo instructions.
2. Authenticate to Azure.
3. Point Azure CLI at the lab subscription.
4. Run a small command first, then a grouped pass.

## Example Session

Authenticate and select the subscription:

```bash
az login
az account set --subscription <lab-subscription-id>
```

Confirm identity and visible subscription context:

```bash
azurefox --outdir ./azurefox-lab whoami --output table
```

Run an initial census:

```bash
azurefox --outdir ./azurefox-lab inventory --output table
```

Run a grouped sweep once the basics look right:

```bash
azurefox --outdir ./azurefox-lab all-checks --output table
```

If you want a narrower pass first:

```bash
azurefox --outdir ./azurefox-lab all-checks --section identity --output table
```

## Why The Lab Helps

- It gives you a known environment to validate command behavior.
- It makes screenshots and walkthroughs easier to reproduce.
- It reduces the temptation to learn AzureFox for the first time in a production tenant.

## Practical Tip

Use a dedicated `--outdir` like `./azurefox-lab` so the resulting artifacts stay grouped
together while you compare runs.
