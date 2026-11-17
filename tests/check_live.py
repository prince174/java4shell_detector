"""Run the live ten-version acceptance matrix against the Compose GUI API."""
import argparse
import csv
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
from urllib.request import Request, urlopen

ALL_VERSIONS = {
    "17.0.5", "17.0.6", "17.0.7", "17.0.8", "17.0.9",
    "17.0.10", "17.0.11", "17.0.12", "17.0.13", "21.0.5",
}
CANDIDATE_VERSIONS = ALL_VERSIONS - {"17.0.5", "21.0.5"}
EXPECTED = {"assets": 10, "findings": 10, "candidates": 8, "errors": 0}


def verify_build_settings():
    root = Path(__file__).resolve().parents[1]
    expected = {"GOPROXY": "https://nexus.example.invalid/repository/go/",
                "GOSUMDB": "sum.golang.org https://nexus.example.invalid/repository/sumdb/"}
    env = {key: value for key, value in os.environ.items() if key not in expected}
    with tempfile.TemporaryDirectory() as tmp:
        settings = Path(tmp, ".env")
        for values in ({key: "" for key in expected}, expected):
            settings.write_text("".join(f"{key}={value}\n" for key, value in values.items()), encoding="utf-8")
            config = subprocess.check_output(
                ["docker", "compose", "--env-file", str(settings), "config", "--format", "json"],
                cwd=root, env=env,
            )
            assert json.loads(config)["services"]["inventory"]["build"]["args"] == values


def request(base, path, settings=None):
    data = None if settings is None else json.dumps(settings).encode()
    headers = {} if data is None else {"Content-Type": "application/json"}
    with urlopen(Request(base + path, data=data, headers=headers), timeout=15) as response:
        return response.read()


def verify(base, source, job, java_majors):
    run_id = job["id"]
    if job["state"] != "done":
        raise AssertionError(f"{source} {run_id}: {job['state']} {job['messages']}")
    root = f"/reports/{source}/{run_id}/"
    report = json.loads(request(base, root + "inventory.json"))
    candidates = list(csv.DictReader(io.StringIO(request(base, root + "candidates.csv").decode("utf-8-sig"))))
    expected_versions = CANDIDATE_VERSIONS if 17 in java_majors else set()
    if 21 in java_majors:
        expected_versions = expected_versions | {"21.0.5"}
    expected = {**EXPECTED, "candidates": len(expected_versions)}
    assert report["summary"] == expected, (source, report["summary"])
    assert report["scope"]["java_majors"] == java_majors
    assert {row["version"].partition("+")[0] for row in report["findings"]} == ALL_VERSIONS
    assert len(candidates) == len(expected_versions)
    assert {row["version"].partition("+")[0] for row in candidates} == expected_versions
    results = json.loads(request(base, f"/api/results/{source}?page=1"))
    assert results["total"] == len(results["items"]) == 10
    assert results["javaMajors"] == java_majors and all(item["url"] for item in results["items"])
    assert job["http"]["count"] > 0 and not job["http"]["errors"]
    if source == "nexus":
        assert len({row["digest"] for row in report["assets"]}) == len(ALL_VERSIONS)
        assert {row["platform"] for row in report["assets"]} == {"linux/amd64"}
        assert all(row["vendor"] == "Eclipse Adoptium" and row["evidence"].endswith("/release")
                   for row in report["findings"])
        assert job["registry"]["count"] and not job["registry"]["errors"]
    else:
        assert all(row["status"] == "scanned" and row["commit"] for row in report["assets"])
    print(f"{source} {run_id}: {expected}, {job['elapsed']:.2f} s", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default="http://127.0.0.1:18084")
    parser.add_argument("--timeout", type=int, default=300)
    parser.add_argument("--java-majors", default="17")
    parser.add_argument("--profile", choices=("inventory", "java4shell"), default="inventory")
    args = parser.parse_args()
    verify_build_settings()
    base = args.url.rstrip("/")
    java_majors = ([8, 17, 21, 25, 27] if args.profile == "java4shell"
                   else sorted({int(major) for major in args.java_majors.split(",")}))
    assert b"Data Center" in request(base, "/") and b"data-route" in request(base, "/architecture")
    options = {
        "bitbucket": {"provider": "cloud", "projects": ",".join(f"J4S{i:02d}" for i in range(1, 11))},
        "nexus": {"repositories": "java4shell-fixtures"},
    }
    current = json.loads(request(base, "/api/status"))
    if any(row["state"] == "running" for row in current.values()):
        raise RuntimeError("An inventory scan is already running")
    run_ids = {}
    for source, filters in options.items():
        body = {**filters, "delay": 0.1, "javaMajors": args.java_majors, "profile": args.profile}
        run_ids[source] = json.loads(request(base, f"/api/start/{source}", body))["id"]
    print(f"Started live scans {run_ids}", flush=True)
    deadline = time.monotonic() + args.timeout
    while time.monotonic() < deadline:
        jobs = json.loads(request(base, "/api/status"))
        if any(jobs[source]["id"] != run_id for source, run_id in run_ids.items()):
            raise RuntimeError("Another scan replaced a job before validation")
        if all(job["state"] != "running" for job in jobs.values()):
            for source in run_ids:
                verify(base, source, jobs[source], java_majors)
            return
        time.sleep(3)
    raise TimeoutError("Live inventory scans did not finish in time")


if __name__ == "__main__":
    main()
