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

DEFAULT_JAVA_MAJORS = (17,)
JAVA4SHELL_MAJORS = (8, 17, 21, 25, 27)
JAVA4SHELL = "CVE-2026-114938"
ORACLE_FIXED = {
    17: (17, 0, 21, 1),
    21: (21, 0, 13, 1),
    25: (25, 0, 5, 1),
    27: (27, 0, 1, 1),
}
VERSION = re.compile(
    r"(?<![\d.])(?P<major>1[7-9]|2[0-9]|[3-9][0-9]|[5-9]|1[0-6])"
    r"(?:\.(?P<minor>\d+)(?:\.(?P<patch>\d+)(?:\.\d+)*)?)?"
    r"(?:[+_]\d+(?:-LTS)?|-ea(?:\+\d+)?)?(?![\d.])",
    re.IGNORECASE,
)
LEGACY_VERSION = re.compile(
    r"(?<![\d.])(?:1\.(?P<major>[5-8])(?:\.\d+)?(?:_(?P<update>\d+))?"
    r"|(?P<short_major>[5-8])u(?P<short_update>\d+))(?:-?b\d+)?(?:-perf)?(?![\d.])",
    re.IGNORECASE,
)


def parse_java_majors(value):
    parts = [part.strip() for part in value.split(",")] if isinstance(value, str) else []
    if not parts or any(not re.fullmatch(r"[5-9]|[1-9][0-9]", part) for part in parts):
        raise ValueError("Укажи мажорные версии Java от 5 до 99 через запятую, например 17,21,25,27")
    return tuple(sorted({int(part) for part in parts}))


def classify(value, java_majors=DEFAULT_JAVA_MAJORS):
    legacy = LEGACY_VERSION.search(value)
    if legacy:
        major = int(legacy["major"] or legacy["short_major"])
        return legacy[0], "candidate" if major in java_majors else "outside_scope"
    match = VERSION.search(value)
    if not match:
        return "", "unknown_version"
    version = match[0]
    major, minor, patch = match.groups()
    if int(major) not in java_majors:
        return version, "outside_scope"
    if major != "17":
        return version, "candidate"
    if patch is None:
        return version, "unknown_version"
    status = "candidate" if (int(minor), int(patch)) >= (0, 6) else "outside_scope"
    return version, status


def java4shell_result(row):
    version = row.get("version", "")
    vendor = row.get("vendor", "").lower()
    product_version = row.get("product_version") or (version if version.startswith("21.3.") else "")
    if re.fullmatch(r"21\.3\.20(?:\.0\.3)?(?:\+\d+)?", product_version):
        return "candidate", "Check the Oracle GraalVM Enterprise Edition build listed in the advisory"
    legacy = LEGACY_VERSION.fullmatch(version)
    if version == "8" or legacy and (legacy["major"] or legacy["short_major"]) == "8":
        update = (legacy["update"] or legacy["short_update"]) if legacy else None
        if vendor and "oracle" not in vendor:
            return "outside_scope", "Java 8 entry in the advisory applies to Oracle Performance"
        if update and int(update) >= 513:
            return "outside_scope", "Oracle Java 8 November update or later"
        if version.lower().endswith("-perf"):
            return "candidate", "Oracle Java 8 Performance; verify the exact update and build"
        if update in (None, "511"):
            return "candidate", "Verify whether this is Oracle Java 8 Performance"
        return "unknown_version", "Oracle Java 8 Performance edition could not be established"
    _, status = classify(version, JAVA4SHELL_MAJORS)
    if vendor in {"oracle", "oracle corporation", "oracle java se", "oracle jdk"} and not row.get("distribution"):
        number = re.match(r"\d+(?:\.\d+)*", version)
        if number:
            parts = tuple(map(int, number[0].split(".")))
            fixed = ORACLE_FIXED.get(parts[0])
            if fixed and parts >= fixed:
                return "outside_scope", "Oracle Java SE fixed baseline or later"
    if status == "unknown_version" and re.fullmatch(r"17(?:\.\d+)?", version):
        return "candidate", "Verify whether Java 17 is 17.0.6 or later"
    reason = "Affected Java branch; verify vendor build and patch level" if status == "candidate" else ""
    return status, reason


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
        operation = path.split("?", 1)[0]
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
            raise RuntimeError(f"HTTP {exc.code} at {operation}") from None
        except (URLError, OSError) as exc:
            status = None
            raise RuntimeError(f"Request failed at {operation}: {exc}") from None
        finally:
            self.finished_at = time.monotonic()
            report_progress(self.progress, "http", self.finished_at - started_at,
                            status is not None and 200 <= status < 300, operation,
                            http_status=status, target=self.base)
        if len(data) > max_bytes:
            raise ValueError(f"Response exceeds {max_bytes} bytes at {operation}")
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
    rule = "Selected Java major versions; Java 17 requires version >= 17.0.6"
    if scope.get("profile") == "java4shell":
        rule = JAVA4SHELL + " inventory candidates; verify runtime, vendor and patch level"
        for row in findings:
            if "policy_reason" not in row:
                row["status"], row["policy_reason"] = java4shell_result(row)
    candidates = [row for row in findings if row["status"] == "candidate"]
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "rule": rule,
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
              "declared_version", "product_version", "status", "policy_reason", "file", "evidence", "line")
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
