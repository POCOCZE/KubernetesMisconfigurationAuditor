![Command output](images/top-image.png)

# Kubernetes misconfiguration auditor

CLI tool that connects to Kubernetes cluster and audits workloads for common misconfigurations, improving cluster stability and efficiency. 

## The spec

It checks for:

1. **Pods/containers without resource requests or limits**
2. **Pods/containers running as root**
3. **Pods without liveness or readiness probes**
4. **Pods using `latest` tag**
5. **Namespaces to scan** - configurable (default: all non-system namespaces)

## Libraries used

| Library | Purpose |
|---|---|
| `typer` | CLI arguments |
| `pick` | Select which kubernetes cluster to use |
| `kubernetes` | Connect to cluster, list pods, read specs |
| `rich` | Beautiful table output in terminal |
| `dataclass` | Bundle variables together in a class |
| `datetime` | Show time in JSON and YAML formated outputs |
| `json` | Formats data as JSON |
| `yaml` | Formats data as YAML |

## Prerequisites

- **python**
- **uv** or *pip*
- **Kubernetes cluster**

## How to run the tool

1. Clone this repo

```bash
git clone https://github.com/POCOCZE/KubernetesMisconfigurationAuditor.git
cd KubernetesMisconfigurationAuditor
```

2. Create venv and install packages

```bash
# with uv (recommended for this project)
uv sync

# with pip
python -m venv .venv
source .venv/bin/activate  # on Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

3. Run the tool

```bash
# with uv
uv run main.py

# with pip (after activating venv)
python main.py
```

## Available CLI options

![Help option](images/help-image.png)

### JSON output example

Command used: `uv run main.py --namespace n8n --context admin@your-cluster --output json | jq`

```json
[
  {
    "time": "2026-03-21T20:38:14.825467",
    "namespace": "n8n",
    "name": "cnpg-n8n-db-1",
    "container": "postgres",
    "issue": "limits undefined",
    "severity": "low"
  },
  {
    "time": "2026-03-21T20:38:14.825487",
    "namespace": "n8n",
    "name": "n8n-test-65b6888646-76qk2",
    "container": "n8n",
    "issue": "no resources defined",
    "severity": "high"
  },
  {
    "time": "2026-03-21T20:38:14.825487",
    "namespace": "n8n",
    "name": "n8n-test-65b6888646-76qk2",
    "container": "n8n",
    "issue": "container runs as root",
    "severity": "critical"
  }
]
```

### YAML output example

Command used: `uv run main.py --namespace n8n --context admin@your-cluster --output yaml`

```yaml
- container: postgres
  issue: limits undefined
  name: cnpg-n8n-db-1
  namespace: n8n
  severity: low
  time: '2026-03-21T20:41:00.735650'
- container: n8n
  issue: no resources defined
  name: n8n-test-65b6888646-76qk2
  namespace: n8n
  severity: high
  time: '2026-03-21T20:41:00.735669'
- container: n8n
  issue: container runs as root
  name: n8n-test-65b6888646-76qk2
  namespace: n8n
  severity: critical
  time: '2026-03-21T20:41:00.735669'
```

## Issues & Contributing

If you have any problems or ideas on other features to add, feel free to open an issue or create Pull Request.
