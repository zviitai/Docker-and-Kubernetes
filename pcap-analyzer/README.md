# PCAP Analyzer

A small SRE-style service that:
1. **Reads** a `.pcap` / `.pcapng` network capture file
2. **Writes** every packet as a document to **Elasticsearch**
3. **Exposes** live counters to **Prometheus** on `/metrics`

---

## Table of Contents
- [What the PCAP contains](#what-the-pcap-contains)
- [Architecture overview](#architecture-overview)
- [Environment variables](#environment-variables)
- [How to run (local Python)](#how-to-run-local-python)
- [How to run (Docker + docker-compose)](#how-to-run-docker--docker-compose)
- [How to run (Kubernetes / Helm)](#how-to-run-kubernetes--helm)
- [Example Elasticsearch document](#example-elasticsearch-document)
- [How to check /metrics](#how-to-check-metrics)
- [Running the unit tests](#running-the-unit-tests)
- [Design decisions (SRE perspective)](#design-decisions-sre-perspective)
- [Production improvements](#production-improvements)

---

## What the PCAP contains

The sample `sample.pcap` is a **pcapng** capture of real mixed traffic.
A quick breakdown of the first 30 000 packets:

| Protocol | Count  | Notes                          |
|----------|--------|--------------------------------|
| TCP      | ~10 800 | HTTP, HTTPS, custom ports      |
| UDP      | ~10 600 | DNS, NTP, other UDP traffic    |
| ICMP     | ~240   | Ping / traceroute style        |
| Other    | ~8 300 | ARP, non-IPv4 frames           |

Key observations from an SRE point of view:
- The mix of TCP and UDP is roughly equal → good test of the protocol branching logic.
- ARP packets have no IP layer, so they land in the `other` bucket — the code handles them gracefully instead of crashing.
- Timestamps are in UTC ISO-8601 so they sort naturally in Kibana.

---

## Architecture overview

```
sample.pcap
     │
     ▼
┌─────────────────────────────────────────┐
│            main.py (Python)             │
│                                         │
│  open_reader()  ── dpkt ──▶ raw frames  │
│  parse_packet() ──────────▶ flat dict   │
│  write_to_elastic() ───────▶ ES index   │
│  Prometheus counters updated on each    │
│  packet                                 │
└──────────┬──────────────────────────────┘
           │                   │
    :9200  ▼                   ▼  :9100
  Elasticsearch           /metrics
  (+ Kibana :5601)       Prometheus
```

---

## Environment variables

| Variable           | Required | Default                    | Description                          |
|--------------------|----------|----------------------------|--------------------------------------|
| `PCAP_PATH`        | Yes*     | —                          | Path to the .pcap/.pcapng file       |
| `ELASTIC_URL`      | No       | `http://localhost:9200`    | Elasticsearch base URL               |
| `ELASTIC_INDEX`    | No       | `pcap-packets`             | Index name for packet documents      |
| `ELASTIC_USERNAME` | No       | —                          | ES username (if auth is enabled)     |
| `ELASTIC_PASSWORD` | No       | —                          | ES password (if auth is enabled)     |
| `METRICS_PORT`     | No       | `9100`                     | Port for the Prometheus /metrics endpoint |

\* `PCAP_PATH` can also be passed as the first CLI argument: `python main.py sample.pcap`

---

## How to run (local Python)

### Prerequisites
- **Python 3.9+** installed — check with `python --version`
- **Docker Desktop** installed and **running** (whale icon in taskbar must be active)

### Step 1 — Install Python dependencies

```bash
pip install -r requirements.txt
```

> On Windows if `pip` is not found, try `python -m pip install -r requirements.txt`

### Step 2 — Start Elasticsearch + Kibana

```bash
docker compose up -d
```

Wait ~30 seconds for Elasticsearch to become healthy. You can check:
```bash
docker compose ps
# elasticsearch should show "healthy"
```

### Step 3 — Run the analyser

**Windows (Git Bash / PowerShell):**
```bash
# Git Bash
ELASTIC_URL=http://localhost:9200 PCAP_PATH=sample.pcap python main.py

# PowerShell
$env:ELASTIC_URL="http://localhost:9200"; $env:PCAP_PATH="sample.pcap"; python main.py

# Command Prompt (cmd.exe)
set ELASTIC_URL=http://localhost:9200 && set PCAP_PATH=sample.pcap && python main.py
```

**Mac / Linux:**
```bash
ELASTIC_URL=http://localhost:9200 PCAP_PATH=sample.pcap python main.py
```

The service logs progress every 1 000 packets and keeps running after
finishing so `/metrics` stays reachable.

---

## How to run (Docker + docker-compose)

### Start the full stack (ES + Kibana + analyser)

```bash
# 1. Build the analyser image
docker build -t pcap-analyzer:latest .

# 2. Start ES + Kibana
docker compose up -d

# 3. Run the analyser as a one-shot container
docker run --rm \
  --network pcap-analyzer_default \
  -e ELASTIC_URL=http://elasticsearch:9200 \
  -e PCAP_PATH=/data/sample.pcap \
  -v $(pwd)/sample.pcap:/data/sample.pcap:ro \
  -p 9100:9100 \
  pcap-analyzer:latest
```

Open Kibana at **http://localhost:5601** → Discover → select index `pcap-packets`.

---

## How to run (Kubernetes / Helm)

Step-by-step guide to deploy the full stack on a local Kubernetes cluster using Minikube and Helm.

### Prerequisites

Install the following tools on Windows (run in PowerShell as Administrator):

```powershell
winget install Kubernetes.minikube
winget install Helm.Helm
```

Restart PowerShell after installation so the tools are on your PATH.

### Step 1: Start Minikube

```powershell
minikube start --driver=docker
```

Verify the cluster is running:

```powershell
kubectl get nodes
```

Expected output: one node with status `Ready`.

### Step 2: Build the Docker Image Inside Minikube

The image must be built inside Minikube's Docker daemon so Kubernetes can pull it without a registry.

```powershell
minikube docker-env | Invoke-Expression
docker build -t pcap-analyzer:latest .
```

### Step 3: Add the Elastic Helm Repository

```powershell
helm repo add elastic https://helm.elastic.co
helm repo update
```

### Step 4: Deploy Elasticsearch

Create a values file to disable security (required for plain HTTP access):

```powershell
@"
replicas: 1
minimumMasterNodes: 1
esConfig:
  elasticsearch.yml: |
    xpack.security.enabled: false
    xpack.security.transport.ssl.enabled: false
resources:
  requests:
    memory: 512Mi
    cpu: 100m
  limits:
    memory: 1Gi
"@ | Set-Content -Path "$HOME\es-values.yaml" -Encoding ASCII

helm install elasticsearch elastic/elasticsearch -f "$HOME\es-values.yaml"
```

> **Note:** If Elasticsearch still rejects HTTP connections (the official Helm chart ignores `esConfig` in some versions), use the plain manifest instead:

```powershell
@"
apiVersion: v1
kind: Service
metadata:
  name: elasticsearch-master
spec:
  selector:
    app: elasticsearch
  ports:
    - port: 9200
      targetPort: 9200
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: elasticsearch
spec:
  replicas: 1
  selector:
    matchLabels:
      app: elasticsearch
  template:
    metadata:
      labels:
        app: elasticsearch
    spec:
      containers:
        - name: elasticsearch
          image: docker.elastic.co/elasticsearch/elasticsearch:8.13.0
          env:
            - name: discovery.type
              value: single-node
            - name: xpack.security.enabled
              value: "false"
            - name: ES_JAVA_OPTS
              value: "-Xms512m -Xmx512m"
          ports:
            - containerPort: 9200
"@ | Set-Content -Path "$HOME\elasticsearch.yaml" -Encoding ASCII

kubectl apply -f "$HOME\elasticsearch.yaml"
```

### Step 5: Wait for Elasticsearch to Be Ready

```powershell
kubectl get pods -w
```

Wait until `elasticsearch-*` shows `1/1 Running` (takes ~60 seconds on first run due to image pull).

### Step 6: Verify Elasticsearch is Responding

```powershell
kubectl run test-curl --image=curlimages/curl --rm -it --restart=Never -- curl http://elasticsearch-master:9200
```

Expected: JSON response containing `"cluster_name"` and `"You Know, for Search"`.

### Step 7: Deploy the PCAP Analyzer via Helm

```powershell
helm install pcap-release ./helm/pcap-analyzer `
  --set elasticsearch.url=http://elasticsearch-master:9200 `
  --set pcap.path=/data/sample.pcap `
  --set pcapVolume.enabled=false
```

### Step 8: Verify Everything is Running

```powershell
kubectl get pods
```

Expected output:

```
NAME                                          READY   STATUS    RESTARTS   AGE
elasticsearch-...                             1/1     Running   0          ...
pcap-release-pcap-analyzer-...               1/1     Running   0          ...
```

### Step 9: Check the Logs

```powershell
kubectl logs deployment/pcap-release-pcap-analyzer
```

Expected: lines like `POST http://elasticsearch-master:9200/pcap-packets/_doc [status:201 ...]`  
and finally: `Finished. Total packets processed: 5705`

### Useful kubectl / Helm Commands

| Action | Command |
|--------|---------|
| List all pods | `kubectl get pods` |
| Watch pods live | `kubectl get pods -w` |
| View app logs | `kubectl logs deployment/pcap-release-pcap-analyzer` |
| Describe a pod | `kubectl describe pod <pod-name>` |
| Restart the app | `kubectl rollout restart deployment/pcap-release-pcap-analyzer` |
| List Helm releases | `helm list` |
| Uninstall app | `helm uninstall pcap-release` |
| Uninstall Elasticsearch | `helm uninstall elasticsearch` or `kubectl delete -f "$HOME\elasticsearch.yaml"` |
| Stop Minikube | `minikube stop` |
| Delete cluster | `minikube delete` |

---

## Example Elasticsearch document

Every packet is stored as a flat JSON document:

```json
{
  "timestamp":     "2026-05-16T06:09:25.525702Z",
  "packet_length": 182,
  "src_ip":        "82.207.20.117",
  "dst_ip":        "192.166.135.211",
  "src_port":      8291,
  "dst_port":      56294,
  "l4_protocol":   "tcp"
}
```

Fields that don't apply to the packet type are stored as `null`
(e.g., `src_port`/`dst_port` for ICMP, `src_ip`/`dst_ip` for ARP).

### Query all TCP packets in Kibana Dev Tools

```
GET pcap-packets/_search
{
  "query": { "term": { "l4_protocol": "tcp" } },
  "size": 10
}
```

---

## How to check /metrics

While the analyser is running, open a second terminal:

```bash
curl http://localhost:9100/metrics
```

Expected output (example):

```
# HELP pcap_packets_total Total packets processed, by L4 protocol
# TYPE pcap_packets_total counter
pcap_packets_total{protocol="tcp"}   10815.0
pcap_packets_total{protocol="udp"}   10660.0
pcap_packets_total{protocol="icmp"}    242.0
pcap_packets_total{protocol="other"}  8283.0

# HELP pcap_bytes_total Total bytes of all packets processed, by L4 protocol
# TYPE pcap_bytes_total counter
pcap_bytes_total{protocol="tcp"}   8432190.0
pcap_bytes_total{protocol="udp"}   1543220.0
...

# HELP pcap_elastic_write_total Elasticsearch write attempts
# TYPE pcap_elastic_write_total counter
pcap_elastic_write_total{status="success"}  29810.0
pcap_elastic_write_total{status="fail"}         0.0
```

---

## Running the unit tests

```bash
pip install pytest
pytest tests/ -v
```

Tests cover:
- TCP packet parsing (IP, ports, timestamp, length)
- UDP packet parsing
- ICMP packet parsing (no ports expected)
- Non-IP frames (ARP) → `l4_protocol = "other"`, `src_ip = null`
- Garbage bytes → no crash, returns safe defaults

---

## Design decisions (SRE perspective)

### Why dpkt and not Scapy?
`dpkt` is a lightweight, fast library with zero native dependencies. In
production you want your base Docker image small and build times short.
Scapy is more feature-rich but much heavier and imports slowly.

### Why a flat Elasticsearch document?
Flat documents are easy to query, filter, and visualise in Kibana
without nested-field complexity. For more advanced use (e.g., payload
analysis) a nested structure could be added later.

### Why keep the process alive after processing?
The Prometheus `/metrics` endpoint must stay up so Prometheus can scrape
it on its own schedule (default 15 s). If the process exits immediately
the data is lost before Prometheus pulls it.

### Why exponential back-off on ES writes?
Elasticsearch can be temporarily overloaded. A simple 1-2-4 second
back-off gives the cluster time to recover without hammering it.
The `fail` counter in Prometheus makes it immediately visible if
documents are being dropped.

### Why read environment variables instead of a config file?
The [12-Factor App](https://12factor.net/config) pattern — config in
env vars is the standard for containerised workloads. It makes the
same Docker image usable in dev, staging, and production with no
rebuild.

---

## Production improvements

| Area | Current | Production improvement |
|------|---------|----------------------|
| **Throughput** | Packet-by-packet writes | Bulk-index API (send 500 docs per request) |
| **Reliability** | In-memory metrics | Persist metrics to a remote write endpoint |
| **Security** | Auth via plain env vars | Mount credentials from Kubernetes Secrets / Vault |
| **Observability** | Basic logging | Structured JSON logs (e.g., `python-json-logger`) shipped to a log aggregator |
| **Scalability** | Single process | Stream large pcaps in chunks; distribute via Kafka |
| **PCAP source** | Local file only | Watch a directory / S3 bucket for new captures |
| **ES index** | Fixed name | Date-based index (`pcap-packets-YYYY.MM.DD`) + ILM policy for auto-deletion |
