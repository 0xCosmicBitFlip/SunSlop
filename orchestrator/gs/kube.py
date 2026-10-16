"""Pods in this namespace. Nothing else."""
import json
import os
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request

from gs.model import ACTIVITY, log

class Kube:
    def __init__(self, namespace, seat_label="gamestream"):
        host = os.environ["KUBERNETES_SERVICE_HOST"]
        port = os.environ.get("KUBERNETES_SERVICE_PORT", "443")
        self.base = f"https://{host}:{port}"
        self.ns = namespace or open("/var/run/secrets/kubernetes.io/serviceaccount/namespace").read().strip()
        self.token_path = "/var/run/secrets/kubernetes.io/serviceaccount/token"
        self.ca = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
        self.seat_label = seat_label
        self._cache = []
        self._cached = 0.0

    def _token(self):
        return open(self.token_path).read().strip()

    def request(self, method, path, body=None, content_type="application/json"):
        data = None if body is None else json.dumps(body).encode()
        req = urllib.request.Request(self.base + path, data=data, method=method)
        req.add_header("Authorization", "Bearer " + self._token())
        if data is not None:
            req.add_header("Content-Type", content_type)
        ctx = ssl.create_default_context(cafile=self.ca)
        try:
            with urllib.request.urlopen(req, context=ctx, timeout=30) as resp:
                raw = resp.read()
                return resp.status, json.loads(raw) if raw else None
        except urllib.error.HTTPError as exc:
            raw = exc.read()
            try:
                parsed = json.loads(raw) if raw else None
            except json.JSONDecodeError:
                parsed = {"message": raw.decode("utf-8", "replace")[:400]}
            return exc.code, parsed

    def invalidate(self):
        self._cached = 0.0

    def list_seats(self):
        now = time.monotonic()
        if self._cache and now - self._cached < 1.0:
            return self._cache
        code, data = self.request(
            "GET",
            f"/api/v1/namespaces/{self.ns}/pods?labelSelector={urllib.parse.quote('app=' + self.seat_label, safe='')}",
        )
        if code != 200:
            log(f"list pods: {code} {data}")
            return self._cache
        self._cache = data.get("items", [])
        self._cached = now
        return self._cache

    def get_pod(self, name):
        code, data = self.request("GET", f"/api/v1/namespaces/{self.ns}/pods/{name}")
        if code == 404:
            return None
        if code != 200:
            log(f"get {name}: {code} {data}")
            return None
        return data

    def create_pod(self, pod):
        self.invalidate()
        return self.request("POST", f"/api/v1/namespaces/{self.ns}/pods", pod)

    def delete_pod(self, name):
        self.invalidate()
        return self.request(
            "DELETE",
            f"/api/v1/namespaces/{self.ns}/pods/{name}?gracePeriodSeconds=15",
        )

    def patch_pod(self, name, body):
        self.invalidate()
        return self.request(
            "PATCH",
            f"/api/v1/namespaces/{self.ns}/pods/{name}",
            body,
            "application/merge-patch+json",
        )

    def list_apps(self, names):
        found = []
        seen = set()
        for name in names:
            code, data = self.request(
                "GET",
                f"/api/v1/namespaces/{self.ns}/pods?labelSelector={urllib.parse.quote('app=' + name, safe='')}",
            )
            if code != 200:
                continue
            for pod in data.get("items", []):
                uid = ((pod.get("metadata") or {}).get("uid")
                       or (pod.get("metadata") or {}).get("name"))
                if uid in seen:
                    continue
                seen.add(uid)
                found.append(pod)
        return found


def pod_gpu(pod):
    raw = (pod.get("metadata", {}).get("labels") or {}).get("gamestream.local/gpu")
    try:
        return int(raw)
    except (TypeError, ValueError):
        return None


def pod_phase(pod):
    return (pod.get("status") or {}).get("phase") or ""


def pod_ip(pod):
    return (pod.get("status") or {}).get("podIP")


def activity_unix(pod):
    raw = ((pod.get("metadata") or {}).get("annotations") or {}).get(ACTIVITY)
    try:
        return int(raw)
    except (TypeError, ValueError):
        return None


def pod_node(pod):
    return (pod.get("spec") or {}).get("nodeName")


def pod_ready(pod):
    for cond in (pod.get("status") or {}).get("conditions") or []:
        if cond.get("type") == "Ready" and cond.get("status") == "True":
            return True
    return False

