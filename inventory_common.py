"""Shared version policy, HTTP transport and report writer."""
import csv
import json
import os
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

VERSION = re.compile(
    r"(?<![\d.])(?P<major>1[7-9]|2[0-9]|[3-9][0-9]|[5-9]|1[0-6])"
    r"(?:\.(?P<minor>\d+)\.(?P<patch>\d+)(?:\.\d+)?)?"
    r"(?:[+_]\d+(?:-LTS)?|-ea(?:\+\d+)?)?(?![\d.])",
    re.IGNORECASE,
)


def classify(value):
    legacy = re.match(r"^1\.([5-8])(?:\.\d+)?(?:_\d+)?", value)
    if legacy:
        return legacy[0], "outside_scope"
    match = VERSION.search(value)
    if not match:
        return "", "unknown_version"
    version = match[0]
    major, minor, patch = match.groups()
    if major != "17":
        return version, "outside_scope"
    if patch is None:
        return version, "unknown_version"
    status = "candidate" if (int(minor), int(patch)) >= (0, 6) else "outside_scope"
    return version, status


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class Api:
    def __init__(self, base, authorization, timeout, delay=0, progress=False, allow_http_auth=False):
        parsed = urlsplit(base)
        if (parsed.scheme not in {"http", "https"} or not parsed.hostname
                or parsed.username or parsed.password or parsed.query or parsed.fragment):
            raise ValueError("Expected a base HTTP(S) URL without credentials or query")
        if authorization and parsed.scheme != "https" and not allow_http_auth:
            raise ValueError("Authenticated REST requests require HTTPS")
        self.base = base.rstrip("/")
        self.authorization = authorization
        self.timeout = timeout
        self.delay = delay
        self.progress = progress
        self.finished_at = None
        self.opener = build_opener(NoRedirect())

    def read(self, path, params=None, max_bytes=32 * 1024 * 1024, accept="application/json"):
        query = "?" + urlencode(params) if params else ""
        headers = {"Accept": accept}
        if self.authorization:
            headers["Authorization"] = self.authorization
        request = Request(self.base + path + query, headers=headers)
        if self.finished_at is not None:
            deadline = self.finished_at + self.delay
            while (remaining := deadline - time.monotonic()) > 0:
                time.sleep(remaining)
        started_at = time.monotonic()
        status = None
        try:
            with self.opener.open(request, timeout=self.timeout) as response:
                status = response.status
                data = response.read(max_bytes + 1)
        except HTTPError as exc:
            status = exc.code
            exc.close()
            raise RuntimeError(f"HTTP {exc.code} at {path}") from None
        except (URLError, OSError) as exc:
            status = None
            raise RuntimeError(f"Request failed at {path}: {exc}") from None
        finally:
            self.finished_at = time.monotonic()
            report_progress(self.progress, "http", self.finished_at - started_at,
                            status is not None and 200 <= status < 300, path, http_status=status)
        if len(data) > max_bytes:
            raise ValueError(f"Response exceeds {max_bytes} bytes at {path}")
        return data

    def json(self, path, params=None):
        return json.loads(self.read(path, params))


def report_progress(enabled, kind, elapsed, ok, operation, **details):
    if enabled:
        print(json.dumps({"event": kind, "seconds": round(elapsed, 4), "ok": ok,
                          "operation": operation, **details}), flush=True)


def write_reports(output, scope, assets, findings, errors):
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    candidates = [row for row in findings if row["status"] == "candidate"]
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "rule": "Java 17, version >= 17.0.6 within major 17; inventory criterion",
        "scope": scope,
        "summary": {"assets": len(assets), "findings": len(findings),
                    "candidates": len(candidates), "errors": len(errors)},
        "assets": assets, "findings": findings, "errors": errors,
    }
    (output / "inventory.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    fields = ("source", "project", "repository", "branch", "commit", "image", "tag", "reference",
              "index_digest", "digest", "platform", "role", "vendor", "version",
              "declared_version", "status", "evidence", "line")
    with (output / "candidates.csv").open("w", encoding="utf-8-sig", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for row in candidates:
            writer.writerow({
                key: "'" + val if isinstance(val, str) and val.lstrip().startswith(
                    ("=", "+", "-", "@")
                ) else val
                for key, val in row.items()
            })
    print(f"{output}: {len(assets)} assets, {len(candidates)} candidate rows, {len(errors)} errors")
    return 2 if errors else 0


def load_env():
    """Load local settings without printing their values."""
    path = Path(__file__).resolve().with_name(".env")
    if not path.is_file():
        return
    for number, line in enumerate(path.read_text(encoding="utf-8-sig").splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        key, separator, value = line.partition("=")
        key, value = key.strip(), value.strip()
        if not separator or not re.fullmatch(r"[A-Za-z_]\w*", key):
            raise ValueError(f"Invalid .env entry at line {number}")
        if value.startswith(("'", '"')):
            if len(value) < 2 or value[-1] != value[0]:
                raise ValueError(f"Unclosed .env quote at line {number}")
            value = value[1:-1]
        os.environ.setdefault(key, value)
