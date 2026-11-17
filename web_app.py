"""Local web console for the Bitbucket and Nexus inventory jobs."""
import argparse
import json
import math
import os
import subprocess
import sys
import threading
import time
from functools import lru_cache
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, quote, urlencode, urlsplit
from uuid import uuid4

from inventory_common import load_env, parse_java_majors

ROOT = Path(__file__).resolve().parent
SCRIPTS = {"bitbucket": "bitbucket_inventory.py", "nexus": "nexus_inventory.py"}
REPORTS = {"inventory.json": "application/json", "candidates.csv": "text/csv; charset=utf-8"}
LOCK = threading.Lock()
JOBS = {}
OUTPUT = Path(os.getenv("INVENTORY_REPORT_DIR", str(ROOT / "reports")))
PAGE_SIZE = 10


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
    if "javaMajors" in settings:
        majors = parse_java_majors(settings["javaMajors"])
        flags.append("--java-majors=" + ",".join(map(str, majors)))
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


def browser_base(value):
    url = urlsplit(value)
    if url.scheme not in {"http", "https"} or not url.hostname or url.username or url.password:
        return ""
    if url.hostname == "host.docker.internal":
        url = url._replace(netloc=f"127.0.0.1:{url.port}" if url.port else "127.0.0.1")
    return url._replace(query="", fragment="").geturl().rstrip("/")


@lru_cache(maxsize=4)
def result_groups(path, stamp):
    report = json.loads(path.read_text(encoding="utf-8"))
    scope = report["scope"]
    source = scope["source"]
    cloud = scope.get("provider") == "cloud"
    override = "BITBUCKET_WEB_URL" if source == "bitbucket" else "NEXUS_WEB_URL"
    base = browser_base(os.getenv(override) or scope["url"]) if not cloud else "https://bitbucket.org"
    groups = {}
    for row in report["findings"]:
        repository = row["repository"]
        evidence_url = ""
        if source == "nexus":
            image = row["image"]
            reference = row.get("reference") or row.get("tag") or row["digest"]
            key = (repository, image, reference)
            separator = "@" if reference.startswith("sha256:") else ":"
            title = f"{image}{separator}{reference}"
            asset_path = quote(f"v2/{image}/manifests/{reference}", safe="")
            url = f"{base}/#browse/browse:{quote(repository, safe='')}:{asset_path}" if base else ""
        else:
            key = (repository,)
            title = repository
            owner, slug = (quote(part, safe="") for part in repository.split("/", 1))
            root = f"{base}/{owner}/{slug}" if cloud else f"{base}/projects/{owner}/repos/{slug}"
            url = root if cloud else root + "/browse" if base else ""
            file = row.get("file") or row["evidence"].rpartition(" (")[0]
            if url and file and row.get("commit"):
                path_name = quote(file)
                if cloud:
                    evidence_url = f"{root}/src/{quote(row['commit'], safe='')}/{path_name}#lines-{row['line']}"
                else:
                    revision = urlencode({"at": row["commit"]})
                    evidence_url = f"{root}/browse/{path_name}?{revision}#{row['line']}"
        group = groups.setdefault(key, {"title": title, "repository": repository, "url": url, "findings": []})
        group["findings"].append({**row, "url": evidence_url})
    return [groups[key] for key in sorted(groups)], scope.get("java_majors", [17]), report["generated_at"]


def results_page(source, page, candidates):
    if page < 1:
        raise ValueError("Номер страницы должен быть положительным")
    paths = ((path.stat().st_mtime_ns, path) for path in (OUTPUT / source).glob("*/inventory.json")
             if (path.parent / "candidates.csv").is_file())
    latest = max(paths, default=None)
    if latest is None:
        return {"items": [], "total": 0, "page": 1, "pages": 1, "generatedAt": None}
    stamp, path = latest
    groups, majors, generated_at = result_groups(path, stamp)
    if candidates:
        groups = [group for group in groups if any(row["status"] == "candidate" for row in group["findings"])]
    pages = max(1, (len(groups) + PAGE_SIZE - 1) // PAGE_SIZE)
    page = min(page, pages)
    start = (page - 1) * PAGE_SIZE
    return {"items": groups[start:start + PAGE_SIZE], "total": len(groups), "page": page,
            "pages": pages, "javaMajors": majors, "generatedAt": generated_at}


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
        request = urlsplit(self.path)
        path = request.path
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
        source = path.removeprefix("/api/results/")
        if path.startswith("/api/results/") and source in SCRIPTS:
            query = parse_qs(request.query)
            try:
                page = int(query.get("page", ["1"])[0])
                data = results_page(source, page, query.get("candidates") == ["1"])
            except ValueError as exc:
                self.json_response(400, {"error": str(exc)})
            except (KeyError, OSError):
                self.json_response(500, {"error": "Отчёт недоступен"})
            else:
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
