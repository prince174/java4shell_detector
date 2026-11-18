"""Local web console for the Bitbucket and Nexus inventory jobs."""
import argparse
import json
import logging
import math
import os
import re
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
DIAGNOSTIC_LIMIT = 20
LOGGER = logging.getLogger("java4shell_detector")
LOG_LEVELS = ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")


def redact_diagnostic(value):
    message = str(value)
    for key, secret in os.environ.items():
        if secret and key.startswith(("BITBUCKET_", "NEXUS_")) and key.endswith(("_TOKEN", "_PASSWORD")):
            message = message.replace(secret, "[скрыто]").replace(quote(secret, safe=""), "[скрыто]")
    message = re.sub(r"(https?://)[^/@\s]+@", r"\1[скрыто]@", message)
    message = re.sub(r"(?i)([?&](?:access_token|token|password|api_key)=)[^&\s]+",
                     r"\1[скрыто]", message)
    return message.replace("\r", " ").replace("\n", " ")[:800]


def diagnostic(source, job, value):
    line = redact_diagnostic(value)
    LOGGER.debug("[%s %s] %s", source, job["id"], line)
    with LOCK:
        if line not in job["diagnostics"] and len(job["diagnostics"]) < DIAGNOSTIC_LIMIT:
            job["diagnostics"].append(line)


def stats():
    return {"count": 0, "errors": 0, "total": 0.0, "last": None, "max": 0.0,
            "operation": None, "method": None, "http_status": None}


def update_stats(row, event):
    duration = event["seconds"]
    row["count"] += 1
    row["errors"] += int(not event["ok"])
    row["total"] += duration
    row.update(last=duration, max=max(row["max"], duration), operation=event["operation"],
               method=event.get("method"), http_status=event.get("http_status"))


def run_job(source, job, flags):
    output = OUTPUT / source / job["id"]
    command = [sys.executable, "-u", str(ROOT / SCRIPTS[source]),
               "--output", str(output), "--progress", *flags]
    code = 1
    LOGGER.info("[%s %s] started (%s)", source, job["id"], job["provider"])
    try:
        with subprocess.Popen(command, cwd=ROOT, stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT, text=True, encoding="utf-8",
                              errors="replace") as process:
            for line in process.stdout:
                try:
                    event = json.loads(line)
                except ValueError:
                    event = {}
                if event.get("event") in {"http", "registry", "git"}:
                    event["operation"] = redact_diagnostic(event["operation"].split("?", 1)[0])
                    with LOCK:
                        update_stats(job[event["event"]], event)
                    if job["debug"]:
                        operation = event["operation"]
                        status = "OK" if event["ok"] else "ошибка"
                        if event["event"] == "http":
                            operation = f"{event.get('method', 'GET')} {event.get('target', '')}{operation}"
                            status = event.get("http_status") or "нет HTTP-ответа"
                        detail = f"{operation} — {status} ({event['seconds']} с)"
                        if event["ok"]:
                            LOGGER.debug("[%s %s] %s", source, job["id"], redact_diagnostic(detail))
                        else:
                            if event.get("error"):
                                detail += " — " + event["error"]
                            diagnostic(source, job, detail)
                elif line.strip():
                    with LOCK:
                        job["messages"] = [*job["messages"][-9:], redact_diagnostic(line.rstrip())]
            code = process.wait()
    except OSError as exc:
        diagnostic(source, job, f"Запуск скрипта — {exc}")
    summary = None
    try:
        if (output / "inventory.json").is_file():
            report = json.loads((output / "inventory.json").read_text(encoding="utf-8"))
            summary = report["summary"]
            for row in report["errors"][:DIAGNOSTIC_LIMIT]:
                context = " / ".join(str(row[key]) for key in
                                     ("stage", "repository", "branch", "file", "image", "tag") if row.get(key))
                diagnostic(source, job, f"{context or source} — {row['error']}")
    except (ValueError, KeyError, OSError) as exc:
        diagnostic(source, job, f"Чтение отчёта — {exc}")
    if summary is None and code:
        for message in job["messages"]:
            diagnostic(source, job, message)
    partial = code == 2 and summary and summary["assets"]
    level = logging.INFO if code == 0 else logging.WARNING if partial else logging.ERROR
    LOGGER.log(level, "[%s %s] exit=%s, report_errors=%s",
               source, job["id"], code, summary["errors"] if summary else "n/a")
    with LOCK:
        job.update(state="done" if code == 0 else "partial" if partial else "failed",
                   elapsed=time.monotonic() - job["started"], summary=summary,
                   reports=[name for name in REPORTS if (output / name).is_file()])


def make_flags(source, settings):
    delay = float(settings.get("delay", 0.1))
    if not math.isfinite(delay) or delay < 0:
        raise ValueError("Задержка должна быть числом от нуля")
    flags = [f"--delay={delay}"]
    if "profile" in settings:
        profile = settings["profile"]
        if profile not in ("inventory", "java4shell"):
            raise ValueError("Неизвестный профиль поиска")
        flags.append(f"--profile={profile}")
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
        file = ""
        project = ""
        if source == "nexus":
            image = row["image"]
            reference = row.get("reference") or row.get("tag") or row["digest"]
            key = (repository, image, reference)
            separator = "@" if reference.startswith("sha256:") else ":"
            title = f"{image}{separator}{reference}"
            asset_path = quote(row.get("asset_path") or f"v2/{image}/manifests/{reference}", safe="")
            url = f"{base}/#browse/browse:{quote(repository, safe='')}:{asset_path}" if base else ""
        else:
            key = (repository,)
            if row["status"] != "candidate" or key in groups:
                continue
            title = repository
            owner, slug = (quote(part, safe="") for part in repository.split("/", 1))
            project = row.get("project") or ("Без проекта" if cloud else repository.split("/", 1)[0])
            root = f"{base}/{owner}/{slug}" if cloud else f"{base}/projects/{owner}/repos/{slug}"
            url = root if cloud else root + "/browse" if base else ""
            file = row.get("file") or row["evidence"].rsplit(" (", 1)[0]
            if url and file and row.get("commit"):
                path_name = quote(file)
                if cloud:
                    evidence_url = f"{root}/src/{quote(row['commit'], safe='')}/{path_name}#lines-{row['line']}"
                else:
                    revision = urlencode({"at": row["commit"]})
                    evidence_url = f"{root}/browse/{path_name}?{revision}#{row['line']}"
        group = groups.setdefault(key, {"title": title, "repository": repository, "url": url,
                                        "project": project, "findings": []})
        group["findings"].append({**row, "url": evidence_url, **({"file": file} if file else {})})
    ordered = sorted(groups.values(), key=lambda group: (group["project"], group["title"]))
    return (ordered, scope.get("java_majors", [17]),
            scope.get("profile", "inventory"), report["generated_at"])


def results_page(source, page, candidates):
    if page < 1:
        raise ValueError("Номер страницы должен быть положительным")
    paths = ((path.stat().st_mtime_ns, path) for path in (OUTPUT / source).glob("*/inventory.json")
             if (path.parent / "candidates.csv").is_file())
    latest = max(paths, default=None)
    if latest is None:
        return {"items": [], "total": 0, "page": 1, "pages": 1, "generatedAt": None}
    stamp, path = latest
    groups, majors, profile, generated_at = result_groups(path, stamp)
    if candidates:
        groups = [group for group in groups if any(row["status"] == "candidate" for row in group["findings"])]
    pages = max(1, (len(groups) + PAGE_SIZE - 1) // PAGE_SIZE)
    page = min(page, pages)
    start = (page - 1) * PAGE_SIZE
    return {"items": groups[start:start + PAGE_SIZE], "total": len(groups), "page": page,
            "pages": pages, "javaMajors": majors, "profile": profile, "generatedAt": generated_at}


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
                provider = next((flag.partition("=")[2] for flag in flags if flag.startswith("--provider=")), source)
                job = {"id": uuid4().hex, "state": "running", "started": time.monotonic(),
                       "http": stats(), "registry": stats(), "git": stats(), "messages": [], "reports": [],
                       "provider": provider, "diagnostics": [], "debug": LOGGER.isEnabledFor(logging.DEBUG)}
                JOBS[source] = job
        if active:
            self.json_response(409, {"error": "Опрос этого источника уже выполняется"})
            return
        threading.Thread(target=run_job, args=(source, job, flags), daemon=True).start()
        self.json_response(202, {"id": job["id"]})

    def log_message(self, format, *args):
        if urlsplit(self.path).path not in {"/api/status", "/api/config"}:
            LOGGER.debug("%s %s", self.address_string(), redact_diagnostic(format % args))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()
    load_env()
    level = os.getenv("INVENTORY_LOG_LEVEL", "DEBUG").strip().upper()
    if level not in LOG_LEVELS:
        parser.error("INVENTORY_LOG_LEVEL must be " + ", ".join(LOG_LEVELS))
    logging.basicConfig(level=level, format="%(levelname)s %(name)s %(message)s", stream=sys.stdout)
    with ThreadingHTTPServer((args.host, args.port), Handler) as server:
        LOGGER.info("java4shell_detector listening on %s:%s", args.host, args.port)
        server.serve_forever()


if __name__ == "__main__":
    main()
