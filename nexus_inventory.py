"""Inventory Java runtimes in Nexus Docker repositories using crane."""
import argparse
import base64
import json
import math
import os
import posixpath
import re
import secrets
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
from pathlib import Path
from urllib.parse import quote, unquote, urlsplit

from inventory_common import (
    Api, ApiHttpError, ApiTimeoutError, DEFAULT_JAVA_MAJORS, JAVA4SHELL_MAJORS, classify, load_env, parse_java_majors,
    redact_diagnostic, report_progress, write_reports,
)

API_ROOT = "/service/rest/v1"
DISCOVERY_MODES = ("auto", "rest", "extdirect")
EXTDIRECT_FALLBACK_CODES = {403, 404, 405}
ERRORS = (RuntimeError, ValueError, KeyError, TypeError, OSError, tarfile.TarError)
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
MANIFEST_PATH = re.compile(r"(?:^|/)v2/(.+)/manifests/([^/]+)$")
BROWSE_TAG_PATH = re.compile(r"^v2/(.+)/tags/([^/]+)$")
IMAGE_NAME = re.compile(r"[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*(?:/[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*)*")
TAG = re.compile(r"[\w][\w.-]{0,127}", re.ASCII)
RUNTIME_FILE = re.compile(r"(?:^|/)(?:bin/java(?:\.exe)?|libjvm\.so|libjvm\.dylib|jvm\.dll)$", re.I)


def extdirect_read(api, action, method, params):
    target = urlsplit(api.base)
    csrf = secrets.token_hex(16)
    headers = {
        "Content-Type": "application/json",
        "X-Nexus-UI": "true",
        "X-Requested-With": "XMLHttpRequest",
        "Origin": f"{target.scheme}://{target.netloc}",
        "Referer": api.base + "/",
        "NX-ANTI-CSRF-TOKEN": csrf,
        "Cookie": f"NX-ANTI-CSRF-TOKEN={csrf}",
    }
    payload = {"action": action, "method": method, "data": [params], "type": "rpc", "tid": 1}
    response = json.loads(api.read("/service/extdirect", data=json.dumps(payload).encode(),
                                   extra_headers=headers))
    result = response.get("result") if isinstance(response, dict) else None
    if not isinstance(result, dict) or result.get("success") is not True:
        message = response.get("message") if isinstance(response, dict) else None
        if not message and isinstance(result, dict):
            message = result.get("message")
        raise RuntimeError(f"Nexus ExtDirect {action}.{method} failed: {message or 'invalid RPC response'}")
    rows = result.get("data")
    if not isinstance(rows, list):
        raise ValueError(f"Nexus ExtDirect {action}.{method} returned an unexpected result")
    return rows


def repository_catalog(api, discovery):
    if discovery != "extdirect":
        try:
            return api.json(API_ROOT + "/repositories")
        except (ApiHttpError, ApiTimeoutError) as exc:
            if discovery != "auto" or (isinstance(exc, ApiHttpError) and exc.status not in EXTDIRECT_FALLBACK_CODES):
                raise
    return extdirect_read(api, "coreui_Repository", "readReferences", {})


def repository_assets(api, repository):
    pending = ["v2"]
    seen = set()
    while pending:
        node = pending.pop()
        if node in seen:
            continue
        seen.add(node)
        entries = extdirect_read(api, "coreui_Browse", "read",
                                 {"repositoryName": repository, "node": node})
        for entry in entries:
            path = unquote(entry["id"])
            if not path.startswith(unquote(node) + "/") or path == "v2/blobs":
                continue
            if entry.get("leaf") is False or entry.get("type") == "folder":
                pending.append(entry["id"])
            elif MANIFEST_PATH.fullmatch(path) or BROWSE_TAG_PATH.fullmatch(path):
                yield {"path": path}


def endpoint(value):
    if "://" not in value:
        value = "https://" + value
    parsed = urlsplit(value)
    prefix = parsed.path.strip("/")
    if (parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username
            or parsed.password or parsed.query or parsed.fragment
            or (prefix and not IMAGE_NAME.fullmatch(prefix))):
        raise ValueError("Expected a registry host[:port][/prefix] with optional http(s) scheme")
    # A single-label registry requires an explicit port to avoid Docker Hub shorthand.
    if "." not in parsed.netloc and ":" not in parsed.netloc and parsed.netloc != "localhost":
        raise ValueError("Use a fully qualified registry host or specify its port")
    return parsed.netloc, prefix, parsed.scheme == "http"


class Registry:
    def __init__(self, args, workdir):
        self.args = args
        self.workdir = workdir
        self.env = dict(os.environ)
        self.username = os.getenv("NEXUS_DOCKER_USERNAME")
        self.password = os.getenv("NEXUS_DOCKER_PASSWORD")
        if bool(self.username) != bool(self.password):
            raise ValueError("Set both NEXUS_DOCKER_USERNAME and NEXUS_DOCKER_PASSWORD")
        self.rest_host = None
        if not self.username:
            self.username = os.getenv("NEXUS_REST_USERNAME")
            self.password = os.getenv("NEXUS_REST_PASSWORD")
            if self.username and self.password:
                self.rest_host = urlsplit(args.url).hostname
        self.auth_host = None
        for key in ("BITBUCKET_TOKEN", "BITBUCKET_CLOUD_TOKEN", "NEXUS_TOKEN",
                    "NEXUS_REST_PASSWORD", "NEXUS_DOCKER_PASSWORD"):
            self.env.pop(key, None)

    def run(self, command, ref, insecure, *options):
        host = ref.split("/", 1)[0]
        env = self.env.copy()
        if self.username and self.password and (
            self.rest_host is None or urlsplit("//" + host).hostname == self.rest_host
        ):
            if insecure and self.env.get("NEXUS_ALLOW_HTTP_AUTH") != "1":
                raise ValueError("Docker credentials from .env require HTTPS registry endpoints")
            if host != self.auth_host:
                auth = base64.b64encode(f"{self.username}:{self.password}".encode()).decode()
                Path(self.workdir, "config.json").write_text(json.dumps({
                    "auths": {host: {"auth": auth}}
                }), encoding="utf-8")
                self.auth_host = host
            env["DOCKER_CONFIG"] = self.workdir
        command_line = [self.args.crane, command, ref, *options]
        if insecure:
            command_line.append("--insecure")
        started_at = time.monotonic()
        error = ""
        try:
            result = subprocess.run(command_line, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    env=env, timeout=self.args.scan_timeout, check=False)
        except subprocess.TimeoutExpired:
            error = f"crane {command} timed out for {ref}"
        except OSError as exc:
            error = f"crane {command} could not start: {exc.strerror}"
        else:
            if result.returncode:
                output = result.stderr.decode("utf-8", errors="replace").splitlines()
                detail = output[-1] if output else ""
                for key, secret in os.environ.items():
                    if secret and key.startswith(("BITBUCKET_", "NEXUS_")) and key.endswith(("_TOKEN", "_PASSWORD")):
                        detail = detail.replace(secret, "[redacted]").replace(quote(secret, safe=""), "[redacted]")
                detail = re.sub(r"(https?://)[^/@\s]+@", r"\1[redacted]@", detail)
                detail = re.sub(r"(https?://[^\s?]+)\?[^\s]+", r"\1", detail)
                error = f"crane {command} failed for {ref} ({result.returncode}): {detail[:500]}"
        report_progress(self.args.progress, "registry", time.monotonic() - started_at,
                        not error, f"{command} {ref}", **({"error": error} if error else {}))
        if error:
            raise RuntimeError(error)
        return result.stdout

    def manifests(self, name, digest, insecure, platform=None, chain=(), *, on_error=None):
        if not DIGEST.fullmatch(digest) or digest in chain or len(chain) >= 8:
            raise ValueError(f"Invalid or recursive manifest digest: {digest}")
        ref = f"{name}@{digest}"
        manifest = json.loads(self.run("manifest", ref, insecure))
        if "manifests" in manifest:
            for descriptor in manifest["manifests"]:
                labels = descriptor.get("annotations") or {}
                if (labels.get("vnd.docker.reference.type") == "attestation-manifest"
                        or descriptor.get("artifactType")):
                    continue
                child_platform = descriptor.get("platform") or platform
                try:
                    yield from self.manifests(name, descriptor["digest"], insecure,
                                              child_platform, (*chain, digest), on_error=on_error)
                except ERRORS as exc:
                    if on_error is None:
                        raise
                    on_error(descriptor.get("digest"), child_platform, exc)
        elif "layers" in manifest and "config" in manifest:
            if manifest.get("artifactType") or not manifest["config"].get("mediaType", "").endswith(
                ("container.image.v1+json", "image.config.v1+json")
            ):
                return
            if not platform or platform.get("os") in (None, "unknown") or platform.get("architecture") in (None, "unknown"):
                platform = json.loads(self.run("config", ref, insecure))
            os_name, arch = platform.get("os"), platform.get("architecture")
            if not os_name or not arch:
                raise ValueError(f"Missing image platform for {ref}")
            parts = [os_name, arch]
            if platform.get("variant"):
                parts.append(platform["variant"])
            label = "/".join(parts)
            if platform.get("os.version"):
                label += ":" + platform["os.version"]
            yield digest, label
        else:
            raise ValueError(f"Unsupported image manifest for {ref}")


def path_name(name):
    return posixpath.normpath(name.replace("\\", "/")).lstrip("/")


def java_files(archive_path, java_majors=DEFAULT_JAVA_MAJORS):
    releases = {}
    runtime_paths = set()
    with tarfile.open(archive_path, mode="r|*") as archive:
        for member in archive:
            path = path_name(member.name)
            if member.isfile() and posixpath.basename(path).lower() == "release" and member.size <= 65536:
                with archive.extractfile(member) as stream:
                    values = dict(re.findall(r'^([A-Z][A-Z_]+)="([^"\r\n]*)"\s*$',
                                             stream.read().decode("utf-8-sig", errors="replace"), re.M))
                    version = values.get("JAVA_RUNTIME_VERSION") or values.get("JAVA_VERSION")
                    if version:
                        releases[posixpath.dirname(path)] = (
                            path, values.get("IMPLEMENTOR") or values.get("JAVA_VENDOR") or "", version,
                            values.get("GRAALVM_VERSION", ""),
                            "GraalVM" if any("graalvm" in values.get(key, "").lower()
                                             for key in ("IMPLEMENTOR_VERSION", "JAVA_VM_NAME"))
                            or values.get("GRAALVM_VERSION") else "",
                        )
            if RUNTIME_FILE.search(path) and (member.isfile() or member.islnk()):
                runtime_paths.add(path)
    results = []
    matched = set()
    for root, (path, vendor, raw, product_version, distribution) in sorted(
        releases.items(), key=lambda item: -len(item[0])
    ):
        prefix = root + "/" if root else ""
        markers = {marker for marker in runtime_paths - matched if marker.startswith(prefix)
                   and (marker[len(prefix):].lower().startswith(("bin/", "lib/", "jre/")))}
        if markers:
            matched.update(markers)
            version, status = classify(raw, java_majors)
            results.append({"role": "image_runtime", "vendor": vendor, "version": version,
                            "product_version": product_version, "distribution": distribution,
                            "declared_version": raw, "status": status, "evidence": "/" + path,
                            "runtime_files": ["/" + marker for marker in sorted(markers)]})
    # Coalesce bin/java and lib/*/libjvm that belong to the same unversioned runtime.
    remaining = {}
    for path in sorted(runtime_paths - matched):
        root = re.split(r"/(?:bin|lib)/", "/" + path, maxsplit=1)[0]
        remaining.setdefault(root, []).append("/" + path)
    results.extend({"role": "image_runtime", "vendor": "", "version": "",
                    "status": "unknown_version", "evidence": paths[0], "runtime_files": paths}
                   for paths in remaining.values())
    return results


def inventory(api, registry, args, mappings, workdir):
    assets, findings, errors = [], [], []
    scans = {}
    archive_path = Path(workdir, "rootfs.tar")
    try:
        discovery = args.discovery
        catalog = repository_catalog(api, discovery)
        repositories = {repo["name"]: repo for repo in catalog}
        requested = set(args.repository) if args.repository else {
            name for name, repo in repositories.items() if repo["format"] == "docker" and repo["type"] in
            ({"hosted", "proxy"} if args.include_proxy else {"hosted"})
        }
        for repository in sorted(requested):
            try:
                if repository not in repositories:
                    raise ValueError("Repository missing from the Nexus catalog or inaccessible to this account")
                repo_format = repositories[repository]["format"]
                if repo_format != "docker":
                    raise ValueError(f"Nexus repository format is {repo_format!r}. Choose a repository with format 'docker'.")
                if repositories[repository]["type"] not in {"hosted", "proxy"}:
                    raise ValueError("Specify group member repositories individually")
                registry_url = mappings.get(repository)
                if registry_url is None:
                    nexus_url = urlsplit(api.base)
                    registry_url = f"{nexus_url.scheme}://{nexus_url.netloc}/{repository}"
                host, prefix, insecure = endpoint(registry_url)
                seen_refs = {}
                for item in repository_assets(api, repository):
                    match = MANIFEST_PATH.search(item["path"]) or BROWSE_TAG_PATH.fullmatch(item["path"])
                    if match:
                        seen_refs[match.groups()] = item["path"]
                covered = set()
                # Nexus lists both tags and digest aliases as assets. Scan tag references first.
                for image, reference in sorted(seen_refs, key=lambda item: (":" in item[1], *item)):
                    digest_reference = bool(DIGEST.fullmatch(reference))
                    if digest_reference and (image, reference) in covered:
                        continue
                    location = {"source": "nexus", "repository": repository, "image": image,
                                "tag": "" if digest_reference else reference, "reference": reference,
                                "asset_path": seen_refs[image, reference]}
                    index_digest = None
                    errors_before = len(errors)
                    count = 0
                    try:
                        if not IMAGE_NAME.fullmatch(image) or not (TAG.fullmatch(reference) or digest_reference):
                            raise ValueError("Malformed Docker image reference")
                        name = "/".join(part for part in (host, prefix, image) if part)
                        if digest_reference:
                            index_digest = reference
                        else:
                            index_digest = registry.run("digest", f"{name}:{reference}", insecure).decode().strip()
                        def record_manifest_error(digest, platform, error):
                            descriptor = platform or {}
                            label = "/".join(descriptor[key] for key in ("os", "architecture", "variant")
                                             if descriptor.get(key))
                            asset = {**location, "index_digest": index_digest, "digest": digest,
                                     "platform": label, "status": "error"}
                            assets.append(asset)
                            errors.append({**asset, "stage": "read_platform_manifest", "error": str(error)})

                        for digest, platform in registry.manifests(name, index_digest, insecure,
                                                                    on_error=record_manifest_error):
                            count += 1
                            asset = {**location, "index_digest": index_digest, "digest": digest, "platform": platform}
                            try:
                                if digest not in scans:
                                    registry.run("export", f"{name}@{digest}", insecure, str(archive_path))
                                    scans[digest] = java_files(archive_path, args.java_majors)
                                rows = scans[digest]
                                covered.add((image, digest))
                                assets.append({**asset, "status": "scanned", "findings": len(rows)})
                                findings.extend({**asset, **row} for row in rows)
                            except ERRORS as exc:
                                assets.append({**asset, "status": "error"})
                                errors.append({**asset, "error": str(exc)})
                            finally:
                                archive_path.unlink(missing_ok=True)
                        if not count and len(errors) == errors_before:
                            assets.append({**location, "index_digest": index_digest, "status": "no_image_manifests"})
                        if len(errors) == errors_before and count:
                            covered.add((image, index_digest))
                    except ERRORS as exc:
                        if not count:
                            assets.append({**location, "index_digest": index_digest, "status": "error"})
                        errors.append({**location, "index_digest": index_digest, "error": str(exc)})
                if not seen_refs:
                    assets.append({"source": "nexus", "repository": repository, "status": "no_manifest_assets"})
            except ERRORS as exc:
                errors.append({"repository": repository, "error": str(exc)})
    except ERRORS as exc:
        errors.append({"stage": "list_repositories", "error": str(exc)})
    return assets, findings, errors


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url")
    parser.add_argument("--discovery", choices=DISCOVERY_MODES,
                        help="Repository catalog source. Image discovery always uses ExtDirect.")
    parser.add_argument("--profile", choices=("inventory", "java4shell"), default="inventory")
    parser.add_argument("--java-majors", type=parse_java_majors, default=DEFAULT_JAVA_MAJORS,
                        help="Comma-separated Java major versions, e.g. 17,21,25,27 (default: 17)")
    parser.add_argument("--output", default="reports/nexus")
    parser.add_argument("--registry", action="append", default=[], metavar="REPO=ENDPOINT")
    parser.add_argument("--repository", action="append", default=[])
    parser.add_argument("--include-proxy", action="store_true")
    parser.add_argument("--crane", default="crane")
    parser.add_argument("--timeout", type=float, default=30)
    parser.add_argument("--delay", type=float, default=0.1, help="Seconds between REST GET requests")
    parser.add_argument("--progress", action="store_true")
    parser.add_argument("--scan-timeout", type=float, default=900)
    args = parser.parse_args()
    if args.profile == "java4shell":
        args.java_majors = JAVA4SHELL_MAJORS
    if (not all(math.isfinite(value) and value > 0 for value in (args.timeout, args.scan_timeout))
            or not math.isfinite(args.delay) or args.delay < 0):
        parser.error("Use positive timeouts and a non-negative delay")
    try:
        load_env()
        args.discovery = args.discovery or os.getenv("NEXUS_DISCOVERY", "auto")
        if args.discovery not in DISCOVERY_MODES:
            raise ValueError("NEXUS_DISCOVERY must be auto, rest or extdirect")
        args.url = args.url or os.getenv("NEXUS_URL", "")
        mappings = json.loads(os.getenv("NEXUS_REGISTRIES", "{}"))
        if not isinstance(mappings, dict):
            raise ValueError("NEXUS_REGISTRIES must be a JSON object")
        for mapping in args.registry:
            name, sep, value = mapping.partition("=")
            if not name or not sep or not value:
                raise ValueError("Registry mapping must be REPO=ENDPOINT")
            mappings[name] = value
        for value in mappings.values():
            if not isinstance(value, str):
                raise ValueError("Registry endpoints must be strings")
            endpoint(value)
        if not shutil.which(args.crane):
            raise ValueError("crane executable not found; add it to PATH or set --crane")
        token = os.getenv("NEXUS_TOKEN")
        username, password = os.getenv("NEXUS_REST_USERNAME"), os.getenv("NEXUS_REST_PASSWORD")
        if token:
            auth = f"Bearer {token}"
        elif username and password:
            auth = "Basic " + base64.b64encode(f"{username}:{password}".encode()).decode()
        elif username or password:
            raise ValueError("Set both NEXUS_REST_USERNAME and NEXUS_REST_PASSWORD")
        else:
            auth = None
        api = Api(args.url, auth, args.timeout, args.delay, args.progress,
                  allow_http_auth=os.getenv("NEXUS_ALLOW_HTTP_AUTH") == "1")
        with tempfile.TemporaryDirectory(prefix="java4shell-") as workdir:
            registry = Registry(args, workdir)
            result = inventory(api, registry, args, mappings, workdir)
    except ERRORS as exc:
        parser.error(str(exc))
    code = write_reports(args.output, {"source": "nexus", "url": args.url,
                                       "repositories": args.repository,
                                       "include_proxy": args.include_proxy,
                                       "discovery": args.discovery,
                                       "request_delay_seconds": args.delay,
                                       "java_majors": args.java_majors,
                                       "profile": args.profile,
                                       "registry_mappings": mappings}, *result)
    if not args.progress:
        for row in result[2]:
            context = " / ".join(str(row[key]) for key in ("stage", "repository", "image", "reference")
                                 if row.get(key))
            print(redact_diagnostic(f"{context or 'Nexus'}: {row['error']}"), file=sys.stderr)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
