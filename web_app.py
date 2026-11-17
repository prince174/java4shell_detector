"""Local web console for the Bitbucket and Nexus inventory jobs."""
import argparse
import json
import math
import os
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit
from uuid import uuid4

from inventory_common import load_env

ROOT = Path(__file__).resolve().parent
SCRIPTS = {"bitbucket": "bitbucket_inventory.py", "nexus": "nexus_inventory.py"}
REPORTS = {"inventory.json": "application/json", "candidates.csv": "text/csv; charset=utf-8"}
LOCK = threading.Lock()
JOBS = {}
OUTPUT = Path(os.getenv("INVENTORY_REPORT_DIR", str(ROOT / "reports")))


def stats():
    return {"count": 0, "errors": 0, "total": 0.0, "last": None, "max": 0.0,
            "operation": None, "http_status": None}


def update_stats(row, event):
    duration = event["seconds"]
    row["count"] += 1
    row["errors"] += int(not event["ok"])
    row["total"] += duration
    row.update(last=duration, max=max(row["max"], duration), operation=event["operation"],
               http_status=event.get("http_status"))


def run_job(source, job, flags):
    output = OUTPUT / source / job["id"]
    command = [sys.executable, "-u", str(ROOT / SCRIPTS[source]),
               "--output", str(output), "--progress", *flags]
    code = 1
    try:
        with subprocess.Popen(command, cwd=ROOT, stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT, text=True, encoding="utf-8",
                              errors="replace") as process:
            for line in process.stdout:
                try:
                    event = json.loads(line)
                except ValueError:
                    event = {}
                with LOCK:
                    if event.get("event") in {"http", "registry"}:
                        update_stats(job[event["event"]], event)
                    elif line.strip():
                        job["messages"] = [*job["messages"][-9:], line.rstrip()[:500]]
            code = process.wait()
    except OSError as exc:
        with LOCK:
            job["messages"].append(str(exc))
    summary = None
    try:
        if (output / "inventory.json").is_file():
            summary = json.loads((output / "inventory.json").read_text(encoding="utf-8"))["summary"]
    except (ValueError, KeyError, OSError):
        pass
    with LOCK:
        job.update(state={0: "done", 2: "partial" if summary else "failed"}.get(code, "failed"),
                   elapsed=time.monotonic() - job["started"], summary=summary,
                   reports=[name for name in REPORTS if (output / name).is_file()])


def make_flags(source, settings):
    delay = float(settings.get("delay", 0.1))
    if not math.isfinite(delay) or delay < 0:
        raise ValueError("Задержка должна быть числом от нуля")
    flags = [f"--delay={delay}"]
    if source == "bitbucket":
        provider = settings.get("provider", os.getenv("BITBUCKET_PROVIDER", "datacenter"))
        if provider not in ("cloud", "datacenter"):
            raise ValueError("Выберите Bitbucket Cloud или Data Center")
        flags.append(f"--provider={provider}")
    options = {"projects": "project", "branches": "branch"} if source == "bitbucket" else {
        "repositories": "repository"
    }
    for key, option in options.items():
        for item in settings.get(key, "").split(","):
            if item.strip():
                flags.append(f"--{option}={item.strip()}")
    if source == "nexus" and settings.get("includeProxy") is True:
        flags.append("--include-proxy")
    return flags


class Handler(BaseHTTPRequestHandler):
    def respond(self, status, content, media="application/json", headers=None):
        self.send_response(status)
        self.send_header("Content-Type", media)
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(content)

    def json_response(self, status, data):
        self.respond(status, json.dumps(data, ensure_ascii=False).encode("utf-8"),
                     "application/json; charset=utf-8")

    def do_GET(self):
        path = urlsplit(self.path).path
        if path == "/":
            self.respond(200, (ROOT / "index.html").read_bytes(), "text/html; charset=utf-8")
            return
        if path == "/architecture":
            self.respond(200, (ROOT / "docs" / "architecture.html").read_bytes(), "text/html; charset=utf-8")
            return
        if path == "/api/config":
            self.json_response(200, {"bitbucketProvider": os.getenv("BITBUCKET_PROVIDER", "datacenter")})
            return
        if path == "/api/status":
            with LOCK:
                data = json.loads(json.dumps(JOBS))
            for job in data.values():
                if job["state"] == "running":
                    job["elapsed"] = time.monotonic() - job["started"]
                del job["started"]
            self.json_response(200, data)
            return
        parts = path.strip("/").split("/")
        if len(parts) == 4 and parts[0] == "reports":
            _, source, run_id, name = parts
            with LOCK:
                current = JOBS.get(source)
                available = current and current["id"] == run_id and name in current["reports"]
            if available:
                try:
                    content = (OUTPUT / source / run_id / name).read_bytes()
                except OSError:
                    self.json_response(404, {"error": "Отчёт недоступен"})
                else:
                    self.respond(200, content, REPORTS[name],
                                 {"Content-Disposition": f'attachment; filename="{source}-{name}"'})
                return
        self.json_response(404, {"error": "Страница не найдена"})

    def do_POST(self):
        path = urlsplit(self.path).path
        source = path.removeprefix("/api/start/")
        if not path.startswith("/api/start/") or source not in SCRIPTS:
            self.json_response(404, {"error": "Источник не найден"})
            return
        origin = self.headers.get("Origin")
        if origin and urlsplit(origin).netloc != self.headers.get("Host"):
            self.json_response(403, {"error": "Откройте интерфейс сервиса напрямую"})
            return
        try:
            size = int(self.headers.get("Content-Length", "0"))
            if self.headers.get_content_type() != "application/json" or not 0 < size <= 8192:
                raise ValueError("Ожидается JSON размером до 8 КБ")
            settings = json.loads(self.rfile.read(size))
            flags = make_flags(source, settings)
            config_key = "NEXUS_URL"
            if source == "bitbucket":
                config_key = ("BITBUCKET_CLOUD_WORKSPACE" if "--provider=cloud" in flags
                              else "BITBUCKET_URL")
            if not os.getenv(config_key):
                raise ValueError(f"Задайте {config_key} в .env и перезапустите сервис")
        except (ValueError, AttributeError, TypeError) as exc:
            self.json_response(400, {"error": str(exc)})
            return
        with LOCK:
            active = JOBS.get(source, {}).get("state") == "running"
            if not active:
                job = {"id": uuid4().hex, "state": "running", "started": time.monotonic(),
                       "http": stats(), "registry": stats(), "messages": [], "reports": []}
                JOBS[source] = job
        if active:
            self.json_response(409, {"error": "Опрос этого источника уже выполняется"})
            return
        threading.Thread(target=run_job, args=(source, job, flags), daemon=True).start()
        self.json_response(202, {"id": job["id"]})

    def log_message(self, format, *args):
        if self.path != "/api/status":
            super().log_message(format, *args)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()
    load_env()
    with ThreadingHTTPServer((args.host, args.port), Handler) as server:
        print(f"Java4Shell listening on {args.host}:{args.port}", flush=True)
        server.serve_forever()


if __name__ == "__main__":
    main()
