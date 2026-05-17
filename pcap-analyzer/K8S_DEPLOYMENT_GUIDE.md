# PCAP Analyzer — Kubernetes Deployment Guide

Step-by-step commands to deploy the pcap-analyzer stack on a local Kubernetes cluster using Minikube and Helm.

---

## Prerequisites

Install the following tools on Windows (run in PowerShell as Administrator):

```powershell
winget install Kubernetes.minikube
winget install Helm.Helm
```

Restart PowerShell after installation so the tools are on your PATH.

---

## Step 1: Start Minikube

```powershell
minikube start --driver=docker
```

Verify the cluster is running:

```powershell
kubectl get nodes
```

Expected output: one node with status `Ready`.

---

## Step 2: Build the Docker Image Inside Minikube

The image must be built inside Minikube's Docker daemon so Kubernetes can pull it without a registry.

```powershell
minikube docker-env | Invoke-Expression
docker build -t pcap-analyzer:latest .
```

---

## Step 3: Add the Elastic Helm Repository

```powershell
helm repo add elastic https://helm.elastic.co
helm repo update
```

---

## Step 4: Deploy Elasticsearch

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
```

Deploy:

```powershell
helm install elasticsearch elastic/elasticsearch -f "$HOME\es-values.yaml"
```

> **Note:** The official Helm chart ignores the `esConfig` in some versions. If Elasticsearch still rejects HTTP connections, use the plain Kubernetes manifest below instead.

### Alternative: Deploy Elasticsearch via plain manifest

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

---

## Step 5: Wait for Elasticsearch to Be Ready

```powershell
kubectl get pods -w
```

Wait until `elasticsearch-*` shows `1/1 Running` (takes ~60 seconds on first run due to image pull).

---

## Step 6: Verify Elasticsearch is Responding

```powershell
kubectl run test-curl --image=curlimages/curl --rm -it --restart=Never -- curl http://elasticsearch-master:9200
```

Expected: JSON response containing `"cluster_name"` and `"You Know, for Search"`.

---

## Step 7: Deploy the PCAP Analyzer via Helm

```powershell
helm install pcap-release ./helm/pcap-analyzer `
  --set elasticsearch.url=http://elasticsearch-master:9200 `
  --set pcap.path=/data/sample.pcap `
  --set pcapVolume.enabled=false
```

---

## Step 8: Verify Everything is Running

```powershell
kubectl get pods
```

Expected output:

```
NAME                                          READY   STATUS    RESTARTS   AGE
elasticsearch-...                             1/1     Running   0          ...
pcap-release-pcap-analyzer-...               1/1     Running   0          ...
```

---

## Step 9: Check the Logs

```powershell
kubectl logs deployment/pcap-release-pcap-analyzer
```

Expected output: lines like `POST http://elasticsearch-master:9200/pcap-packets/_doc [status:201 ...]`  
and finally: `Finished. Total packets processed: 5705`

---

## Useful Commands

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
