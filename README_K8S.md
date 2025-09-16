This file documents how to build and deploy your target app into a local Kubernetes cluster (minikube / kind / Docker Desktop), then point the dashboard at it.

docker build -t target-app:latest -f ./Dockerfile ..\path\to\target
1) Deploy publicly-available Juice Shop image

This repo now targets the public image `bkimminich/juice-shop:latest` in `k8s/deployment.yaml`.

If you just run locally with Docker you can continue using:

docker run --rm -p 3000:3000 bkimminich/juice-shop

But to run in Kubernetes use one of the workflows below.

2) Minikube (recommended for local testing)

# Use minikube's docker daemon to avoid pushing images
minikube -p minikube docker-env | Invoke-Expression
# (you do not need to build if you use the public image; deployment pulls it)
kubectl apply -f .\k8s\deployment.yaml
kubectl apply -f .\k8s\service.yaml

# get the service URL
minikube service target-app-svc --url

3) Docker Desktop / local k8s

kubectl apply -f .\k8s\deployment.yaml
kubectl apply -f .\k8s\service.yaml

Open http://localhost:30080 (or node IP):30080 in your browser.

4) kind

# If you prefer kind, the deployment will pull the public image automatically
kubectl apply -f .\k8s\deployment.yaml
kubectl apply -f .\k8s\service.yaml

Access via http://localhost:30080 (NodePort) unless your kind setup is different.

5) Configure the dashboard

- Open the dashboard at http://127.0.0.1:5000/dashboard
- Enter the target URL (e.g. the minikube service URL or http://localhost:30080), set Delay (s) to 5, and click Start.

Notes
- `k8s/deployment.yaml` now references `bkimminich/juice-shop:latest` and includes readiness/liveness probes.
- If you want to test your own image instead, replace the `image:` field in `k8s/deployment.yaml` and, if using kind, load your built image into the cluster.
